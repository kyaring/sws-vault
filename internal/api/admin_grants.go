package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

// 授权开关接口（SV-20261016-07 H）：密钥详情（D）与接入方详情（G）共用。
//
//	POST /admin/secrets/{id}/clients                    整体覆盖「这一个密钥」的接入方授权
//	POST /admin/projects/{name}/clients/{id}/secrets     整体覆盖「这一个接入方」在本项目密钥上的授权
//
// 规则：只能授权同一项目内的密钥与接入方，跨项目的 id 一律 400 且库不变；
// 未归入项目的密钥不可授权给任何人；关掉最后一个授权后写「显式空」
// （no_client_access=true），绝不能退回「空列表 = 项目内所有人都能用」。

type rowQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

type rowExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// formIDs 读取表单里某个多值字段（接入方 id 列表 / 密钥 id 列表）。
func formIDs(r *http.Request, field string) []string {
	return dedupStrings(splitCSV(strings.Join(r.Form[field], ",")))
}

func decodeBinding(raw string) (Binding, error) {
	var bd Binding
	if strings.TrimSpace(raw) == "" {
		return bd, nil
	}
	if err := json.Unmarshal([]byte(raw), &bd); err != nil {
		return Binding{}, err
	}
	return bd, nil
}

func saveBinding(q rowExecer, id string, bd Binding) error {
	bb, err := json.Marshal(bd)
	if err != nil {
		return err
	}
	_, err = q.Exec(`UPDATE secrets SET bindings=? WHERE id=?`, string(bb), id)
	return err
}

// idsAllInProject 校验 ids 是否全部属于项目 project 下的一张表（clients / secrets）。
func idsAllInProject(q rowQuerier, table, project string, ids []string) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, project)
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	rows, err := q.Query(`SELECT id FROM `+table+` WHERE ns=? AND id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		found[id] = true
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, id := range ids {
		if !found[id] {
			return false, nil
		}
	}
	return true, nil
}

// projectClientIDs 返回项目内当前启用中的接入方 id。
// 用于把「空列表 = 对全项目开放」显式化成一份名单，避免顺手撤掉别人的权限。
func projectClientIDs(q rowQuerier, project string) ([]string, error) {
	rows, err := q.Query(`SELECT id FROM clients WHERE ns=? AND disabled=0 ORDER BY created_at`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// adminSecretClients 覆盖一个密钥的接入方授权（D「谁在用」的保存地址）。
func (s *Server) adminSecretClients(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/secrets/"), "/clients")
	if !namePattern.MatchString(id) {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	_ = r.ParseForm()
	selected := formIDs(r, "client")
	var ns, raw string
	if e := s.S.DB.QueryRow(`SELECT ns,bindings FROM secrets WHERE id=? AND status='active'`, id).Scan(&ns, &raw); e != nil {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	if ns == unassignedNS {
		adminErrOut(w, http.StatusBadRequest, "未归入项目的密钥不能授权给接入方")
		return
	}
	ok, e := idsAllInProject(s.S.DB, "clients", ns, selected)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		adminErrOut(w, http.StatusBadRequest, "只能授权同一个项目里的接入方")
		return
	}
	bd, e := decodeBinding(raw)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "invalid stored policy")
		return
	}
	// 整体覆盖：只有显式列出的接入方能用；一个都不留时写「显式空」，不是「空 = 所有人」。
	bd.AllowedClients = nil
	if len(selected) > 0 {
		bd.AllowedClients = selected
	}
	bd.NoClientAccess = len(selected) == 0
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()
	if e = saveBinding(tx, id, bd); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not update grants")
		return
	}
	if e = tx.Commit(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not commit grants")
		return
	}
	s.audit("admin", ns, "admin.grant.update", id, "", "ok", s.sourceIP(r))
	// 密钥详情页（D）就绪后改跳 /admin/secrets/{id}。
	http.Redirect(w, r, "/admin/advanced/secrets", http.StatusSeeOther)
}

// adminClientSecrets 覆盖一个接入方在本项目密钥上的授权（G「能用哪些密钥」的保存地址）。
// 只增删这一个接入方，项目里其他接入方的授权不受影响。
func (s *Server) adminClientSecrets(w http.ResponseWriter, r *http.Request, project, clientID string) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !namePattern.MatchString(clientID) {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	_ = r.ParseForm()
	selected := formIDs(r, "secret")
	var clientNS string
	if e := s.S.DB.QueryRow(`SELECT ns FROM clients WHERE id=?`, clientID).Scan(&clientNS); e != nil || clientNS != project {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	chosen := map[string]bool{}
	for _, id := range selected {
		chosen[id] = true
	}
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()
	ok, e := idsAllInProject(tx, "secrets", project, selected)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		adminErrOut(w, http.StatusBadRequest, "只能授权同一个项目里的密钥")
		return
	}
	explicit, e := projectClientIDs(tx, project)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	type secretRow struct{ id, bindings string }
	var list []secretRow
	rows, e := tx.Query(`SELECT id,bindings FROM secrets WHERE ns=? AND status='active'`, project)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for rows.Next() {
		var v secretRow
		if e := rows.Scan(&v.id, &v.bindings); e != nil {
			rows.Close()
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		list = append(list, v)
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for _, v := range list {
		bd, e := decodeBinding(v.bindings)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "invalid stored policy")
			return
		}
		// 「空列表 = 对全项目开放」的密钥先显式化成当前启用中的接入方名单，
		// 再按本次表单增删这一个接入方：谁都不会被静默撤权。
		open := len(bd.AllowedClients) == 0 && !bd.NoClientAccess
		if open {
			bd.AllowedClients = append([]string(nil), explicit...)
			bd.NoClientAccess = false
		}
		has := false
		for _, id := range bd.AllowedClients {
			if id == clientID {
				has = true
			}
		}
		want := chosen[v.id]
		if has == want && !open {
			continue
		}
		if want {
			if !has {
				bd.AllowedClients = append(bd.AllowedClients, clientID)
			}
			bd.NoClientAccess = false
		} else {
			keep := bd.AllowedClients[:0]
			for _, id := range bd.AllowedClients {
				if id != clientID {
					keep = append(keep, id)
				}
			}
			bd.AllowedClients = keep
			if len(bd.AllowedClients) == 0 {
				bd.AllowedClients = nil
				bd.NoClientAccess = true
			}
		}
		if e := saveBinding(tx, v.id, bd); e != nil {
			adminErrOut(w, http.StatusInternalServerError, "could not update grants")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not commit grants")
		return
	}
	s.audit("admin", project, "admin.grant.update", clientID, "", "ok", s.sourceIP(r))
	// 接入方详情页（G）就绪后改跳 /admin/projects/{name}/clients/{id}。
	http.Redirect(w, r, "/admin/projects/"+project, http.StatusSeeOther)
}
