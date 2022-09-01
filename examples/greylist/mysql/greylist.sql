CREATE DATABASE greylist;

CREATE TABLE greylist.sender(
    address varchar(500) NOT null primary key,
    user varchar(500) NOT null,
    domain varchar(500) NOT null
);
