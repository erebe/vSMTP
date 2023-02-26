# mysql

In this folder you can find:

- A `greylist.vsl` file containing a `greylist` function that can be used to query a mysql database.
- A `greylist.sql` file that can be used to generate a simple greylist database.

To generate the greylist using your mysql instance, use the following command:

```sh
$ mysql < greylist.sql
```

## Setup mysql

following this great tutorial: https://www.digitalocean.com/community/tutorials/how-to-install-mysql-on-ubuntu-22-04

This setup has been tested on Ubuntu 22.04, check out https://dev.mysql.com/doc/mysql-installation-excerpt/5.7/en/ for other systems.

TL;DR

```sh
# Install mysql.
$ sudo apt update
$ sudo apt install mysql-server
$ sudo systemctl start mysql.service

# Login as root.
$ sudo mysql

# Replace auth_socket authentication by a simple password.
mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your-password';
mysql> exit

# Update root password & remove unnecessary stuff.
$ sudo mysql_secure_installation

# Connect as root with the password.
mysql -u root -p

# Reset auth to auth_socket, this way you can connect with `sudo mysql`
mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;
```

To manage your database, you should create a new user with restricted privileges instead of relying on root.

```sh
# Here we use localhost as our host but you could also setup your database on another server.
mysql> CREATE USER 'greylist-manager'@'localhost' IDENTIFIED BY 'your-password';
```

Create the database:

```sh
sudo mysql < greylist.sql
```

Grant necessary privileges to your user.

```sh
mysql> GRANT SELECT, INSERT ON greylist.sender TO 'greylist-manager'@'localhost';
```

Everything is now ready to go. You could try to insert data to check that your user has the right privileges.

```sh
$ mysql -u 'greylist-manager' -p
```
