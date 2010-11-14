DROP TABLE stats;

CREATE TABLE stats (
      event_time TIMESTAMP NOT NULL,
      hostname TEXT NOT NULL,
      veid INTEGER NOT NULL,
      resource TEXT NOT NULL,
      held_value BIGINT NOT NULL,
      maxheld_value BIGINT NOT NULL,
      barrier_value BIGINT NOT NULL,
      limit_value BIGINT NOT NULL,
      failcnt_value BIGINT NOT NULL,
      old_failcnt_value BIGINT NOT NULL
);

CREATE INDEX stats_time_idx ON stats (event_time);
