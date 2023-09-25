create table if not exists datasette_insecure_users_users(
  id integer primary key autoincrement,
  username TEXT UNIQUE NOT NULL,
  password_salt BLOB,
  password_hash BLOB
);
