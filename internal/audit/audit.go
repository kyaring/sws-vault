package audit

import (
	"database/sql"
	"time"
)

type Event struct {
	Actor, NS, SecretID, Action, TargetHost, Result, SourceIP string
	At                                                        time.Time
}

func Insert(db *sql.DB, e Event) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	_, err := db.Exec(`INSERT INTO audit(at,actor,ns,secret_id,action,target_host,result,source_ip) VALUES(?,?,?,?,?,?,?,?)`, e.At.UTC().Format(time.RFC3339Nano), e.Actor, e.NS, e.SecretID, e.Action, e.TargetHost, e.Result, e.SourceIP)
	return err
}
