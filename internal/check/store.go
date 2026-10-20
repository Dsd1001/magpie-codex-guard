package check

import (
	"database/sql"
	"encoding/json"
	_ "modernc.org/sqlite"
	"os"
)

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)")
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}
func (s *Store) Load(v *State) error {
	var b []byte
	err := s.db.QueryRow("SELECT body FROM state WHERE id=1").Scan(&b)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (s *Store) Save(v State) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO state(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", b)
	return err
}
func (s *Store) Close() { s.db.Close() }
