ALTER TABLE accounts
    ADD COLUMN privkey BYTEA NOT NULL DEFAULT '',
    ADD COLUMN pubkey BYTEA NOT NULL DEFAULT '';