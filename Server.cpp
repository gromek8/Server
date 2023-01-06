#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8888
#define HOST "127.0.0.1"
#define MAX_CLIENTS 10

void handle_connection(SSL* ssl);


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
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
	{
		printf("WSAStartup failed.\n");
		return 1;
	}

	SSL_CTX* ctx;
	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, "rootCA.crt", NULL);

	// Tworzenie gniazda
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket failed.\n");
		WSACleanup();
		return 1;
	}

	// Struktura z informacjami o adresie serwera
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(PORT);

	// Przypisywanie gniazda do struktury adresowej
	if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("bind failed.\n");
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// Nasłuchiwanie połączeń
	if (listen(sock, SOMAXCONN) < 0)
	{
		printf("listen failed.\n");
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// Tablica gniazd klientów
	SSL* ssl_clients[MAX_CLIENTS];
	for (int i = 0; i < MAX_CLIENTS; i++)
		ssl_clients[i] = NULL;
	// Struktura z informacjami o aktywności gniazd
	WSAPOLLFD fds[MAX_CLIENTS + 1];
	while (1)
	{
		fds[0].fd = sock;
		fds[0].events = POLLRDNORM;
		fds[0].revents = 0;

		// Przepisanie gniazd klientów do struktury
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			if (ssl_clients[i])
			{
				fds[i + 1].fd = SSL_get_fd(ssl_clients[i]);
				fds[i + 1].events = POLLRDNORM;
				fds[i + 1].revents = 0;
			}
			else
			{
				fds[i + 1].fd = INVALID_SOCKET;
				fds[i + 1].events = 0;
				fds[i + 1].revents = 0;
			}
		}

		// Oczekiwanie na aktywność gniazd
		int ret = WSAPoll(fds, MAX_CLIENTS + 1, -1);
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
			X509* client_cert = SSL_get_peer_certificate(ssl_client);
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

			// Autoryzacja klienta na podstawie certyfikatu
			// (można tu zaimplementować własny algorytm autoryzacji)

			// Zwalnianie certyfikatu klienta
			X509_free(client_cert);

			// Szukanie wolnego miejsca w tablicy gniazd klientów
			int free_index = -1;
			for (int i = 0; i < MAX_CLIENTS; i++)
			{
				if (!ssl_clients[i])
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
			ssl_clients[free_index] = ssl_client;
		}

		// Obsługa aktywności gniazd klientów
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			if (fds[i + 1].revents & POLLRDNORM)
				handle_connection(ssl_clients[i]);
		}
	}

	// Zwalnianie zasobów i zamykanie gniazda
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		if (ssl_clients[i])
		{
			SSL_shutdown(ssl_clients[i]);
			SSL_free(ssl_clients[i]);
		}
	}
	closesocket(sock);
	WSACleanup();

	return 0;
}

void handle_connection(SSL* ssl)
{
	// Odbieranie certyfikatu klienta
	char buffer[1024];
	if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0)
	{
		printf("SSL_read failed.\n");
		return;
	}

	// Weryfikacja certyfikatu klienta
	X509* cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		printf("Could not get client certificate.\n");
		return;
	}

	long result = SSL_get_verify_result(ssl);
	if (result != X509_V_OK)
	{
		printf("Certificate verification failed.\n");
		X509_free(cert);
		return;
	}

	// Zwalnianie certyfikatu
	X509_free(cert);

	// Pętla obsługi komend
	while (1)
	{
		// Odbieranie komendy od klienta
		if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0)
		{
			printf("SSL_read failed.\n");
			break;
		}

		const char* serverResponse= "Test text dasdasd\n";
		// Obsługa komendy 'send'
		if (strncmp(buffer, "send", 4) == 0)
		{
			// Otwórz plik do zapisu
			FILE* file = fopen("plik_od_klienta.txt", "wb");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku do zapisu");
				break;
			}
			// Odbieranie danych od klienta
			int n, htr;
			while ((n = SSL_read(ssl, buffer, 1024)) > 0) {
				// Sprawdzanie, czy otrzymano znak konca wysylania danych
				if (strncmp(buffer, "END_OF_FILE", 11) == 0)
				{
					break;
				}
				if (fwrite(buffer, 1, n, file) != n) {
					perror("Nie udało się zapisać danych do pliku");
					break;
				}
			}
			// Sprawdź, czy nie wystąpił błąd podczas odbierania danych
			if (n < 0) {
				printf("SSL_read failed.\n");
				break;
			}
			
		

			// Zamknij plik
			fclose(file);
		}
		// Obsługa komendy 'read'
		else if (strncmp(buffer, "read", 4) == 0)
		{
			// Otwórz plik do odczytu
			FILE* file = fopen("plik_do_wyslania.txt", "rb");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku do odczytu");
				break;
			}
			// Wczytaj dane z pliku i wyślij je do klienta
			int n;
			while ((n = fread(buffer, 1, 1024, file)) > 0) {
				if (SSL_write(ssl, buffer, n) != n) {
					perror("Nie udało się wysłać danych do klienta");
					break;
				}
			}

			// Sprawdź, czy nie wystąpił błąd podczas wczytywania danych z pliku
			if (n < 0) {
				perror("Nie udało się wczytać danych z pliku");
				break;
			}
			SSL_write(ssl, "END_OF_FILE", 11);

			// Zamknij plik
			fclose(file);
		}
	}
}