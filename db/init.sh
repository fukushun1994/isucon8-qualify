#!/bin/bash

ROOT_DIR=$(cd $(dirname $0)/..; pwd)
DB_DIR="$ROOT_DIR/db"
BENCH_DIR="$ROOT_DIR/bench"

export MYSQL_PWD=isucon

mysql -uisucon -e "DROP DATABASE IF EXISTS torb; CREATE DATABASE torb;"
mysql -uisucon torb < "$DB_DIR/schema.sql"

if [ ! -f "$DB_DIR/isucon8q-initial-dataset.sql.gz" ]; then
  echo "Run the following command beforehand." 1>&2
  echo "$ ( cd \"$BENCH_DIR\" && bin/gen-initial-dataset )" 1>&2
  exit 1
fi

mysql -uisucon torb -e 'ALTER TABLE reservations DROP KEY event_id_and_sheet_id_idx'
gzip -dc "$DB_DIR/isucon8q-initial-dataset.sql.gz" | mysql -uisucon torb
mysql -uisucon torb -e 'ALTER TABLE reservations ADD KEY event_id_and_sheet_id_idx (event_id, sheet_id)'

mysql -uisucon torb -e 'CREATE TABLE IF NOT EXISTS sheet_ranks (`rank` VARCHAR(128) NOT NULL PRIMARY KEY, price INTEGER UNSIGNED NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;'
mysql -uisucon torb -e 'INSERT INTO sheet_ranks (`rank`, price) SELECT `rank`, price FROM sheets GROUP BY `rank`;'
#mysql -uisucon torb -e 'ALTER TABLE sheets DROP COLUMN price;'
mysql -uisucon torb -e 'ALTER TABLE reservations ADD INDEX user_id(user_id);'

mysql -uisucon torb -e 'ALTER TABLE reservations ADD COLUMN is_canceled BOOLEAN NOT NULL DEFAULT FALSE;'
mysql -uisucon torb -e 'UPDATE reservations SET is_canceled = TRUE WHERE canceled_at IS NOT NULL'
mysql -uisucon torb -e 'ALTER TABLE reservations ADD INDEX is_canceled(is_canceled);'
mysql -uisucon torb -e 'ALTER TABLE reservations ADD INDEX reserved_at(reserved_at);'
