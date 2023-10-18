# Developer - How to Start Guide

This guide will help developers set up and run the PowerAuth Test Server using Docker.

## PowerAuth Test Server

The PowerAuth Test Server is a containerized environment that allows developers to test the PowerAuth functionality.
It's vital to ensure that all steps are followed properly to get it up and running.

### Pre-requisites

- Ensure Docker is installed and running on your machine.

### Setting Up the Environment

1. **Navigate to the `powerauth-test-server` directory**

   Before executing any command, make sure you are in the correct directory.

    ```
    cd path/to/powerauth-test-server
    ```

2. **Prepare the environment file**

   Copy the provided `env.list.tmp` located in `power-auth-server/docker` to `power-auth-server/env.list`.

    ```
    cp power-auth-server/docker/env.list.tmp power-auth-server/env.list
    ```

   After copying, you may adjust the `power-auth-server/env.list` file according to your specific requirements.


3. **Run the `copy_liquibase.sh` script**

   This script is essential for setting up the database schema for the PowerAuth Test Server.

    ```
    ./copy_liquibase.sh
    ```

   Ensure the script runs successfully without any errors.


4. **Build the Docker image**

   Use the Docker command below to build the PowerAuth Test Server image:

    ```
    docker build -f Dockerfile . -t powerauth-test-server:latest
    ```

### Running the PowerAuth Test Server

1. **Execute the Docker run command**

   Now, to run the server, use the following command:

    ```
    docker run --env-file powerauth-test-server/env.list -d -it -p 8080:8000 --name=pa-test-server powerauth-test-server:latest
    ```

   This command utilizes the prepared environment file for configuration and maps port 8080 of your host to port 8000 of
   the container.

### Additional Information

- **Database Management**: The database schema and migrations for the PowerAuth Test Server are managed using Liquibase.
  This ensures consistency and version control for the database schema.

