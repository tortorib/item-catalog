About Catalog Project:

The application runs in Python accessing an SQLite database. The Python code
delivers a web interface that displays information from the database and allows
specific users the ability to complete forms updating the database. The database
utilizes Oauth to manage access and permissions. Ben's Sporting Goods allows the
end user to view the sports and items for each sport. Based on Oauth login
credentials users can add sports and related items. If the end users credentials
match those of the originating user for a sport that user can edit and or
delete the sport and the related items all other users have view only privileges.

The SQLite database is: application.db;
  There are 3 tables in the database: user, sport, & recently_added

Minimum Requirements:
  Vagrant: https://www.vagrantup.com/downloads.html
  Virtual Box: https://www.virtualbox.org/wiki/Download_Old_Builds_5_1
  README.md about application
  Zipped File: application.py
               application_db_setup.py
               client_secrets.json
               fb_client_secrets.json
               templates directory with html files
               static directory with style.class

-Ensure Virtual Box and Vagrant installed
-Unzip the catalog.zip file in the local Vagrant directory
-Utilizing Git Bash (or the utility of your choice) navigate to the vagrant directory
-Launch the Virtual Box by input: vagrant up
-Connect to the Virtual Box by input:  vagrant ssh
            (vagrant ssh alternatives if it fails: winpty vagrant ssh; or
             VAGRANT_PREFER_SYSTEM_BIN=1 vagrant ssh)
-Navigate to the Vagrant directory
-Navigate to the catalog directory
-Input: python application.py
-The terminal will indicate that the application is running
-Open a web browser and input: localhost:8000/
-Disconnecting input at each prompt: ctrl+c, ctrl+d, vagrant halt
