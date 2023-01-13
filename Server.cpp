#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8888
#define HOST "127.0.0.1"
#define MAX_CLIENTS 10


enum METHOD {
	NONE,
	READ,
	SEND
};

struct Data {
	FILE* file;
	char message_buffor[4048];
	METHOD method;
	SSL* ssl;
};

int handle_connection(Data* client_data, WSAPOLLFD* fd);

void ShowCerts(SSL* ssl)
{
	X509* cert;
	char* line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

int main()
{
	// Inicjalizacja Winsock
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	WSADATA wsa_data;
	// Kontekst ssl
	SSL_CTX* ctx;
	// Socket serwera
	SOCKET sock;
	// Struktura z informacjami o adresie serwera
	struct sockaddr_in server_addr;
	// Struktura z informacjami o aktywności gniazd
	WSAPOLLFD fds[MAX_CLIENTS + 1];
	// Tablica informacji o kliencie
	Data client_data[MAX_CLIENTS];

	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
	{
		printf("WSAStartup failed.\n");
		return 1;
	}

	ctx = SSL_CTX_new(TLS_server_method()); //stworzenie kontekst ssl
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);

		WSACleanup();
		return 1;
	}

	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)// zaczytywanie certyfikatu
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) // zaczytywanie klucza certyfikatu
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	if (!SSL_CTX_check_private_key(ctx)) // weryfikacja poprawności certyfikatu
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);//ustawienie weryfikacji certyfikatów
	SSL_CTX_load_verify_locations(ctx, "rootCA.crt", NULL); //ustawienie bazowego certyfikatu

	// Tworzenie gniazda
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket failed.\n");
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(HOST);
	server_addr.sin_port = htons(PORT);

	// Przypisywanie gniazda do struktury adresowej
	if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("bind failed.\n");
		closesocket(sock);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}

	// Nasłuchiwanie połączeń
	if (listen(sock, SOMAXCONN) < 0)
	{
		printf("listen failed.\n");
		closesocket(sock);
		SSL_CTX_free(ctx);
		WSACleanup();
		return 1;
	}
	//czyszczenie tablicy danych
	for (int i = 0; i < MAX_CLIENTS; i++) {
		client_data[i].ssl = NULL;
		client_data[i].file = NULL;
	}


	while (1)
	{
		fds[0].fd = sock;
		fds[0].events = POLLRDNORM;
		fds[0].revents = 0; //otwiera nasłuchiwanie

		// Przepisanie gniazd klientów do struktury
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			if (!client_data[i].ssl)
			{
				fds[i + 1].fd = INVALID_SOCKET;
				fds[i + 1].events = 0;
				fds[i + 1].revents = 0;
			}
		}

		// Oczekiwanie na aktywność gniazd
		int ret = WSAPoll(fds, MAX_CLIENTS + 1, 5000);//nasłuchiwanie
		if (ret == SOCKET_ERROR)
		{
			printf("WSAPoll failed.\n");
			break;
		}

		// Sprawdzenie aktywności gniazda nasłuchującego
		if (fds[0].revents & POLLRDNORM)
		{
			// Struktura z informacjami o adresie klienta
			struct sockaddr_in client_addr;
			int client_addr_len = sizeof(client_addr);

			// Akceptowanie połączenia
			SOCKET client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_addr_len);
			if (client_sock == INVALID_SOCKET)
			{
				printf("accept failed.\n");
				continue;
			}

			// Tworzenie obiektu SSL
			SSL* ssl_client = SSL_new(ctx);
			if (!ssl_client)
			{
				printf("SSL_new failed.\n");
				closesocket(client_sock);
				continue;
			}

			// Podłączenie gniazda do obiektu SSL
			if (SSL_set_fd(ssl_client, client_sock) != 1)
			{
				printf("SSL_set_fd failed.\n");
				SSL_free(ssl_client);
				closesocket(client_sock);
				continue;
			}
			// Nawiązywanie połączenia SSL
			if (ret = SSL_accept(ssl_client) != 1)
			{
				ERR_print_errors_fp(stderr);
				printf("SSL_accept failed. Error: %d\n", SSL_get_error(ssl_client, ret));
				SSL_free(ssl_client);
				closesocket(client_sock);
				continue;
			}

			ShowCerts(ssl_client);

			// Weryfikacja certyfikatu klienta
			X509* client_cert = SSL_get_peer_certificate(ssl_client);//zaciągniecie certyfikatu
			if (!client_cert)
			{
				printf("SSL_get_peer_certificate failed.\n");
				SSL_shutdown(ssl_client);
				SSL_free(ssl_client);
				closesocket(client_sock);
				continue;
			}

			// Sprawdzenie poprawności certyfikatu klienta
			long verify_result = SSL_get_verify_result(ssl_client);
			if (verify_result != X509_V_OK)
			{
				printf("SSL_get_verify_result failed.\n");
				X509_free(client_cert);
				SSL_shutdown(ssl_client);
				SSL_free(ssl_client);
				closesocket(client_sock);
				continue;
			}

			// Zwalnianie certyfikatu klienta
			X509_free(client_cert);

			// Szukanie wolnego miejsca w tablicy gniazd klientów
			int free_index = -1;
			for (int i = 0; i < MAX_CLIENTS; i++)
			{
				if (!client_data[i].ssl)
				{
					free_index = i;
					break;
				}
			}

			// Jeśli tablica jest pełna, odrzucenie połączenia
			if (free_index == -1)
			{
				printf("No free space for new client.\n");
				SSL_shutdown(ssl_client);
				SSL_free(ssl_client);
				closesocket(client_sock);
				continue;
			}
			// Dodanie nowego klienta do tablicy
			client_data[free_index].ssl = ssl_client;
			client_data[free_index].method = NONE;
			fds[free_index + 1].fd = SSL_get_fd(ssl_client);
			fds[free_index + 1].events = POLLRDNORM;
		}

		// Obsługa aktywności gniazd klientów
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			if (fds[i + 1].revents & POLLRDNORM)
				if (handle_connection(&client_data[i], &fds[i + 1]) == -1) { // klient chce coś wysłać
					printf("Wystąpił błąd");
				};
			if (fds[i + 1].revents & POLLWRNORM) {
				if (handle_connection(&client_data[i], &fds[i + 1]) == -1) { //klient chce coś zaczytać
					printf("Wystąpił błąd");
				};
			}
		}
	}

	// Zwalnianie zasobów i zamykanie gniazda
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		if (client_data[i].ssl)
		{
			SSL_shutdown(client_data[i].ssl);
			SSL_free(client_data[i].ssl);
			fclose(client_data[i].file);
		}
	}

	SSL_CTX_free(ctx);
	closesocket(sock);
	WSACleanup();

	return 0;
}

int handle_connection(Data* client_data, WSAPOLLFD* fd)
{
	char buffer[1025];

	// Weryfikacja certyfikatu klienta
	X509* cert = SSL_get_peer_certificate((*client_data).ssl);
	if (!cert)
	{
		printf("Could not get client certificate.\n");
		return -1;
	}

	long result = SSL_get_verify_result((*client_data).ssl);
	if (result != X509_V_OK)
	{
		printf("Certificate verification failed.\n");
		X509_free(cert);
		return -1;
	}

	(*fd).events = POLLRDNORM; //ustawienie flagi na otwarcie wysyłki

	// Zwalnianie certyfikatu
	X509_free(cert);
	if ((*client_data).method == READ) {
		int n = fread(buffer, 1, 1024, (*client_data).file); //jeżeli przeczyta, wysyła dane do klienta
		if (n > 0)
			if (SSL_write((*client_data).ssl, buffer, n) != n) {
				fclose((*client_data).file);
				(*client_data).method = NONE;
				perror("Nie udało się wysłać danych do klienta");
				return -1;
			}
			else {

				(*fd).events = POLLOUT | POLLWRNORM; //ustawienie flagi do zaczytywania
				return 0;
			}
		// Sprawdź, czy nie wystąpił błąd podczas wczytywania danych z pliku
		if (n < 0) {
			fclose((*client_data).file);
			(*client_data).method = NONE;
			perror("Nie udało się wczytać danych z pliku");
			return -1;
		}
		if (n == 0) {
			SSL_write((*client_data).ssl, "END_OF_FILE", 11);

			(*client_data).method = NONE;
			fclose((*client_data).file);

			return 0;
		}
	}
	// Odbieranie komendy od klienta
	int size = SSL_read((*client_data).ssl, buffer, sizeof(buffer) - 1);
	if (size <= 0)
	{
		printf("SSL_read failed.\n");
		return -1;
	}

	if (strncmp(buffer, "END_OF_FILE", 11) == 0) //informacja o końcu pliku klienta
	{
		fclose((*client_data).file);
		(*client_data).file = NULL;
		(*client_data).method = NONE;
		return 0;
	}

	buffer[size] = '\0'; //zamkniecie stringa

	// Odbieranie danych od klienta
	if ((*client_data).method == SEND) { //sprawdza czy klient jest w trakcie wysyłania
		if (fwrite(buffer, 1, size, (*client_data).file) != size) { //zapis do pliku
			perror("Nie udało się zapisać danych do pliku");
			fclose((*client_data).file);
			(*client_data).file = NULL;
			(*client_data).method = NONE;
			return -1;
		}
	}

	// Obsługa komendy 'send'
	else if (strncmp(buffer, "send", 4) == 0)
	{
		char file_name[20];
		sprintf(file_name, "file_%d.txt", (*fd).fd); //generowanie nazwy plików na podtsawie socketa
		// Otwórz plik do zapisu
		FILE* file = fopen(file_name, "wb");
		if (file == NULL) {
			perror("Nie udało się otworzyć pliku do zapisu");
			return -1;
		}
		(*client_data).method = SEND;
		(*client_data).file = file;
	}
	// Obsługa komendy 'read'
	else if (strncmp(buffer, "read", 4) == 0)
	{
		// Otwórz plik do odczytu
		FILE* file = fopen("plik_do_wyslania.txt", "rb");
		if (file == NULL) {
			perror("Nie udało się otworzyć pliku do odczytu");
			return -1;
		}
		(*client_data).method = READ;
		(*client_data).file = file;
		(*fd).events = POLLOUT | POLLWRNORM;
	}
	else {
		printf("Recieved message: %s", buffer);
	}
	return 0;
}