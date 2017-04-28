SET default_storage_engine=MYISAM;

GRANT ALL PRIVILEGES ON *.*  TO 'openstack_citest'@'%' identified by 'openstack_citest' WITH GRANT OPTION;

DROP DATABASE IF EXISTS openstack_citest;
CREATE DATABASE openstack_citest CHARACTER SET utf8;
