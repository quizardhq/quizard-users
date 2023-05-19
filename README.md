# Quizard Users Microservice

This is a microservice for the Quizard application, which is responsible for handling user-related functionality. It is written in Go and uses a PostgreSQL database for data storage.

## Installation

To run this microservice locally, you will need to have Docker and Go installed on your system. Once you have these dependencies, you can follow the steps below:

1. Clone the repository to your local machine:

```
git clone https://github.com/quizardhq/quizard-users.git
```

2. Change into the project directory:

```
cd quizard-users
```

3. Run the following command to start the microservice and its dependencies (PostgreSQL) with docker:

```
make up-silent
```

This command will build the Docker image for the microservice, start a PostgreSQL container, and then start the microservice in a Docker container. You can then access the microservice at `http://localhost:3006/api/v1` (base url).

## Usage

Once the microservice is up and running, you can use it to perform various user-related operations. The available endpoints are as follows:

- `POST /waitlist/`: Add user to waitlist

## Contributing

If you would like to contribute to this project, feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.

## Credits

This microservice was created by Wizards of Quizard.

### Manage Postgre Instance from browser

```
docker run -p 5050:80 -e 'PGADMIN_DEFAULT_EMAIL=pgadmin4@pgadmin.org' -e 'PGADMIN_DEFAULT_PASSWORD=admin' -d --name pgadmin4 dpage/pgadmin4
```

Open pgAdmin4 in your browser at: <http://localhost:5050>. Note that pgAdmin4 can take a minute or two to start.

- Log in:

Username: pgadmin4@pgadmin.org
Password: admin

- Click Add New Server and fill in the following fields:

Server Name: pg (or whatever you prefer)
On the Connection tab:
Host: host.docker.internal
Port: 5500
Username: postgres
Password: postgrepw
Click Save. You can now explore your databases, schemas and tables.

## Build without Docker

```bash
make run-local
```

Go to <http://localhost:3006>
