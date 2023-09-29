/* 
* Nom du fichier: IPV4packet.c
* Date: 26/09/2023
* Auteur: Despoullains Romain
* Description: Fonctions de manipulation de paquets IPv4
* Version: 1.0
* Notes: https://en.wikipedia.org/wiki/Internet_Protocol_version_4
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
* structure: ipv4_header
* Description: Structure représentant l'en-tête d'un paquet IPv4
* Paramètres:
*   - version_ihl: Version et longueur de l'en-tête (IHL)
*   - type_of_service: Type de service
*   - total_length: Longueur totale
*   - identification: Identification
*   - flags_offset: Drapeaux et offset de fragment
*   - time_to_live: Temps de vie (TTL)
*   - protocol: Protocole
*   - header_checksum: Somme de contrôle de l'en-tête
*   - source_address: Adresse source
*   - destination_address: Adresse de destination
*   - options: Options de l'en-tête (si présentes)
*   - padding: Octets de bourrage (si présents)
*/
struct ipv4_header {
    uint8_t version_ihl; 
    uint8_t type_of_service; 
    uint16_t total_length; 
    uint16_t identification;
    uint16_t flags_offset; 
    uint8_t time_to_live; 
    uint8_t protocol; 
    uint16_t header_checksum; 
    uint32_t source_address; 
    uint32_t destination_address; 
    uint32_t options; 
    uint32_t padding; 
};

/*
* structure: ipv4_packet
* Description: Structure représentant un paquet IPv4
* Paramètres:
*   - header: En-tête du paquet
*   - data: Données du paquet 
*   - data_length: Longueur des données 
*/
struct ipv4_packet {
    struct ipv4_header header; 
    uint8_t *data; 
    uint32_t data_length; 
};

/*
* Fonction: ipv4_header_create
* Description: Création d'un en-tête IPv4
* Paramètres:
*   - version: Version de l'en-tête
*   - ihl: Longueur de l'en-tête
*   - type_of_service: Type de service
*   - total_length: Longueur totale
*   - identification: Identification
*   - flags: Drapeaux
*   - offset: Offset de fragment
*   - time_to_live: Temps de vie (TTL)
*   - protocol: Protocole
*   - header_checksum: Somme de contrôle de l'en-tête
*   - source_address: Adresse source
*   - destination_address: Adresse de destination
*   - options: Options de l'en-tête (si présentes)
*   - padding: Octets de bourrage (si présents)
* Retour: Pointeur vers l'en-tête créé
*/
struct ipv4_header *ipv4_header_create(uint8_t version, uint8_t ihl, uint8_t type_of_service, uint16_t total_length, uint16_t identification, uint8_t flags, uint16_t offset, uint8_t time_to_live, uint8_t protocol, uint16_t header_checksum, uint32_t source_address, uint32_t destination_address, uint32_t options, uint32_t padding) {
    struct ipv4_header *header = malloc(sizeof(struct ipv4_header)); 
    header->version_ihl = (uint8_t)((version << 4) | ihl); 
    header->type_of_service = type_of_service; 
    header->total_length = total_length; 
    header->identification = identification; 
    header->flags_offset = (uint16_t)((flags << 13) | offset); 
    header->time_to_live = time_to_live; 
    header->protocol = protocol; 
    header->header_checksum = header_checksum; 
    header->source_address = source_address; 
    header->destination_address = destination_address; 
    header->options = options; 
    header->padding = padding; 
    return header;  
}

/*
* Fonction: ipv4_header_print
* Description: Affichage d'un en-tête IPv4
* Paramètres:
*   - header: En-tête à afficher
* Retour: Rien
*/
void ipv4_header_print(struct ipv4_header *header) {
    printf("IPv4 Header:\n"); 
    printf("    Version: %d\n", header->version_ihl >> 4); 
    printf("    IHL: %d\n", header->version_ihl & 0x0F); 
    printf("    Type of Service: %d\n", header->type_of_service); 
    printf("    Total Length: %d\n", header->total_length); 
    printf("    Identification: %d\n", header->identification); 
    printf("    Flags: %d\n", header->flags_offset >> 13); 
    printf("    Offset: %d\n", header->flags_offset & 0x1FFF); 
    printf("    Time to Live: %d\n", header->time_to_live); 
    printf("    Protocol: %d\n", header->protocol); 
    printf("    Header Checksum: %d\n", header->header_checksum); 
    printf("    Source Address: %d.%d.%d.%d\n", (header->source_address >> 24) & 0xFF, (header->source_address >> 16) & 0xFF, (header->source_address >> 8) & 0xFF, header->source_address & 0xFF); 
    printf("    Destination Address: %d.%d.%d.%d\n", (header->destination_address >> 24) & 0xFF, (header->destination_address >> 16) & 0xFF, (header->destination_address >> 8) & 0xFF, header->destination_address & 0xFF); 
    printf("    Options: %d\n", header->options); 
    printf("    Padding: %d\n", header->padding); 
}

/*
* Fonction: ipv4_header_destroy
* Description: Destruction d'un en-tête IPv4
* Paramètres:
*   - header: En-tête à détruire
* Retour: Rien
*/
void ipv4_header_destroy(struct ipv4_header *header) {
    free(header); 
}

/*
* Fonction: ipv4_packet_create
* Description: Création d'un paquet IPv4
* Paramètres:
*   - header: En-tête du paquet
*   - data: Données du paquet
*   - data_length: Longueur des données
* Retour: Pointeur vers le paquet créé
*/
struct ipv4_packet *ipv4_packet_create(struct ipv4_header *header, uint8_t *data, uint32_t data_length) {
    struct ipv4_packet *packet = malloc(sizeof(struct ipv4_packet)); 
    packet->header = *header; 
    packet->data = data; 
    packet->data_length = data_length; 
    return packet; 
}

/*
* Fonction: ipv4_packet_print
* Description: Affichage d'un paquet IPv4
* Paramètres:
*   - packet: Paquet à afficher
* Retour: Rien
*/
void ipv4_packet_print(struct ipv4_packet *packet) {
    ipv4_header_print(&packet->header); 
    printf("IPv4 Data:\n"); 
    for (uint32_t i = 0; i < packet->data_length; i++) {
        printf("%02X ", packet->data[i]); 
    }
    printf("\n"); 
}

/*
* Fonction: ipv4_packet_destroy
* Description: Destruction d'un paquet IPv4
* Paramètres:
*   - packet: Paquet à détruire
* Retour: Rien
*/
void ipv4_packet_destroy(struct ipv4_packet *packet) {
    free(packet->data); 
    free(packet); 
}


/*
* Fonction: print_binary
* Description: Affichage binaire d'un entier
* Paramètres:
*   - value: Entier à afficher
*   - bits: Nombre de bits à afficher
* Retour: Rien
*/
void print_binary(uint32_t value, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (value >> i) & 1);
        if (i % 4 == 0) printf(" ");
    }
    printf("\n");
}

/* 
* Fonction: ipv4_header_print_binary
* Description: Affichage binaire d'un en-tête IPv4
* Paramètres:
*   - header: En-tête à afficher
* Retour: Rien
*/
void ipv4_header_print_binary(struct ipv4_header *header) {
    printf("IPv4 Header:\n");
    printf("    Version: ");
    print_binary(header->version_ihl >> 4, 4);
    printf("    IHL: ");
    print_binary(header->version_ihl & 0x0F, 4);
    printf("    Type of Service: ");
    print_binary(header->type_of_service, 8);
    printf("    Total Length: ");
    print_binary(header->total_length, 16);
    printf("    Identification: ");
    print_binary(header->identification, 16);
    printf("    Flags: ");
    print_binary(header->flags_offset >> 13, 3);
    printf("    Offset: ");
    print_binary(header->flags_offset & 0x1FFF, 13);
    printf("    Time to Live: ");
    print_binary(header->time_to_live, 8);
    printf("    Protocol: ");
    print_binary(header->protocol, 8);
    printf("    Header Checksum: ");
    print_binary(header->header_checksum, 16);
    printf("    Source Address: ");
    print_binary(header->source_address, 32);
    printf("    Destination Address: ");
    print_binary(header->destination_address, 32);
    printf("    Options: ");
    print_binary(header->options, 32);
    printf("    Padding: ");
    print_binary(header->padding, 32);
}


/*
* Fonction: ipv4_packet_print_binary
* Description: Affichage binaire d'un paquet IPv4
* Paramètres:
*   - packet: Paquet à afficher
* Retour: Rien
*/
void ipv4_packet_print_binary(struct ipv4_packet *packet) {
    ipv4_header_print_binary(&packet->header);
    printf("IPv4 Data:\n");
    for (uint32_t i = 0; i < packet->data_length; i++) {
        print_binary(packet->data[i], 8);
    }
}

/*
* Fonction: print_hexadecimal
* Description: Affichage hexadécimal d'un entier
* Paramètres:
*   - value: Entier à afficher
*   - bytes: Nombre d'octets à afficher
* Retour: Rien
*/
void print_hexadecimal(uint32_t value, int bytes) {
    for (int i = bytes - 1; i >= 0; i--) {
        printf("%02X ", (value >> (i * 8)) & 0xFF);
    }
    printf("\n");
}

/*
* Fonction: ipv4_header_print_hexadecimal
* Description: Affichage hexadécimal d'un en-tête IPv4
* Paramètres:
*   - header: En-tête à afficher
* Retour: Rien
*/
void ipv4_header_print_hexadecimal(struct ipv4_header *header) {
    printf("IPv4 Header:\n");
    printf("    Version: ");
    print_hexadecimal(header->version_ihl >> 4, 1);
    printf("    IHL: ");
    print_hexadecimal(header->version_ihl & 0x0F, 1);
    printf("    Type of Service: ");
    print_hexadecimal(header->type_of_service, 1);
    printf("    Total Length: ");
    print_hexadecimal(header->total_length, 2);
    printf("    Identification: ");
    print_hexadecimal(header->identification, 2);
    printf("    Flags: ");
    print_hexadecimal(header->flags_offset >> 13, 1);
    printf("    Offset: ");
    print_hexadecimal(header->flags_offset & 0x1FFF, 2);
    printf("    Time to Live: ");
    print_hexadecimal(header->time_to_live, 1);
    printf("    Protocol: ");
    print_hexadecimal(header->protocol, 1);
    printf("    Header Checksum: ");
    print_hexadecimal(header->header_checksum, 2);
    printf("    Source Address: ");
    print_hexadecimal(header->source_address, 4);
    printf("    Destination Address: ");
    print_hexadecimal(header->destination_address, 4);
    printf("    Options: ");
    print_hexadecimal(header->options, 4);
    printf("    Padding: ");
    print_hexadecimal(header->padding, 4);
}

/*
* Fonction: ipv4_packet_print_hexadecimal
* Description: Affichage hexadécimal d'un paquet IPv4
* Paramètres:
*   - packet: Paquet à afficher
* Retour: Rien
*/
void ipv4_packet_print_hexadecimal(struct ipv4_packet *packet) {
    ipv4_header_print_hexadecimal(&packet->header);
    printf("IPv4 Data:\n");
    for (uint32_t i = 0; i < packet->data_length; i++) {
        print_hexadecimal(packet->data[i], 1);
    }
}

/*
* Fonction ipv4_header_create_from_binary
* Description: Création d'un en-tête IPv4 à partir d'une représentation binaire
* Paramètres:
*   - binary: Représentation binaire de l'en-tête
* Retour: Pointeur vers l'en-tête créé
*/
struct ipv4_header *ipv4_header_create_from_binary(uint8_t *binary) {
    return ipv4_header_create(
        binary[0] >> 4,              // version
        binary[0] & 0x0F,            // ihl
        binary[1],                   // type_of_service
        (binary[2] << 8) | binary[3],// total_length
        (binary[4] << 8) | binary[5],// identification
        binary[6] >> 5,              // flags
        ((binary[6] & 0x1F) << 8) | binary[7], // offset
        binary[8],                   // time_to_live
        binary[9],                   // protocol
        (binary[10] << 8) | binary[11], // header_checksum
        (binary[12] << 24) | (binary[13] << 16) | (binary[14] << 8) | binary[15], // source_address
        (binary[16] << 24) | (binary[17] << 16) | (binary[18] << 8) | binary[19], // destination_address
        0,                           // options
        0                            // padding
    );
}

/*
* Fonction: ipv4_packet_create_from_binary
* Description: Création d'un paquet IPv4 à partir d'une représentation binaire
* Paramètres:
*   - binary: Représentation binaire du paquet
*   - length: Longueur de la représentation binaire
* Retour: Pointeur vers le paquet créé
*/
struct ipv4_packet *ipv4_packet_create_from_binary(uint8_t *binary, size_t length) {
    // Extract the header fields from the binary data
    struct ipv4_header *header = ipv4_header_create(
        binary[0] >> 4,              // version
        binary[0] & 0x0F,            // ihl
        binary[1],                   // type_of_service
        (binary[2] << 8) | binary[3],// total_length
        (binary[4] << 8) | binary[5],// identification
        binary[6] >> 5,              // flags
        ((binary[6] & 0x1F) << 8) | binary[7], // offset
        binary[8],                   // time_to_live
        binary[9],                   // protocol
        (binary[10] << 8) | binary[11], // header_checksum
        (binary[12] << 24) | (binary[13] << 16) | (binary[14] << 8) | binary[15], // source_address
        (binary[16] << 24) | (binary[17] << 16) | (binary[18] << 8) | binary[19], // destination_address
        0,                           // options
        0                            // padding
    );

    // Create the IPv4 packet
    struct ipv4_packet *packet = ipv4_packet_create(header, &binary[header->version_ihl & 0x0F * 4], length - (header->version_ihl & 0x0F * 4));

    // Free the memory allocated for the header
    ipv4_header_destroy(header);

    return packet;
}

/*
* Fonction: ipv4_header_create_from_hexadecimal
* Description: Création d'un en-tête IPv4 à partir d'une représentation hexadécimale
* Paramètres:
*   - hexadecimal: Représentation hexadécimale de l'en-tête
* Retour: Pointeur vers l'en-tête créé
*/
struct ipv4_header *ipv4_header_create_from_hexadecimal(const char *hexString, size_t length) {
    // Calculate the length of the binary data
    size_t binary_length = length / 2;
    
    // Allocate memory for binary data
    uint8_t *binary = malloc(binary_length);
    if (binary == NULL) {
        return NULL;
    }
    
    // Convert hexadecimal string to binary data
    for (size_t i = 0; i < binary_length; i++) {
        sscanf(&hexString[i * 2], "%2hhx", &binary[i]);
    }
    
    // Extract the header fields from the binary data
    struct ipv4_header *header = ipv4_header_create(
        binary[0] >> 4,              // version
        binary[0] & 0x0F,            // ihl
        binary[1],                   // type_of_service
        (binary[2] << 8) | binary[3],// total_length
        (binary[4] << 8) | binary[5],// identification
        binary[6] >> 5,              // flags
        ((binary[6] & 0x1F) << 8) | binary[7], // offset
        binary[8],                   // time_to_live
        binary[9],                   // protocol
        (binary[10] << 8) | binary[11], // header_checksum
        (binary[12] << 24) | (binary[13] << 16) | (binary[14] << 8) | binary[15], // source_address
        (binary[16] << 24) | (binary[17] << 16) | (binary[18] << 8) | binary[19], // destination_address
        0,                           // options
        0                            // padding
    );
    
    // Free the memory allocated for the binary data
    free(binary);
    
    return header;
}


/*
* Fonction: ipv4_packet_create_from_hexadecimal
* Description: Création d'un paquet IPv4 à partir d'une représentation hexadécimale
* Paramètres:
*   - hexadecimal: Représentation hexadécimale du paquet
*   - length: Longueur de la représentation hexadécimale
* Retour: Pointeur vers le paquet créé
*/
struct ipv4_packet *ipv4_packet_create_from_hexadecimal(const char *hexString, size_t length) {
    // Calculate the length of the binary data
    size_t binary_length = length / 2;
    
    // Allocate memory for binary data
    uint8_t *binary = malloc(binary_length);
    if (binary == NULL) {
        return NULL;
    }
    
    // Convert hexadecimal string to binary data
    for (size_t i = 0; i < binary_length; i++) {
        sscanf(&hexString[i * 2], "%2hhx", &binary[i]);
    }
    
    // Extract the header fields from the binary data
    struct ipv4_header *header = ipv4_header_create(
        binary[0] >> 4,              // version
        binary[0] & 0x0F,            // ihl
        binary[1],                   // type_of_service
        (binary[2] << 8) | binary[3],// total_length
        (binary[4] << 8) | binary[5],// identification
        binary[6] >> 5,              // flags
        ((binary[6] & 0x1F) << 8) | binary[7], // offset
        binary[8],                   // time_to_live
        binary[9],                   // protocol
        (binary[10] << 8) | binary[11], // header_checksum
        (binary[12] << 24) | (binary[13] << 16) | (binary[14] << 8) | binary[15], // source_address
        (binary[16] << 24) | (binary[17] << 16) | (binary[18] << 8) | binary[19], // destination_address
        0,                           // options
        0                            // padding
    );
    
    // Create the IPv4 packet
    struct ipv4_packet *packet = ipv4_packet_create(header, &binary[header->version_ihl & 0x0F * 4], binary_length - (header->version_ihl & 0x0F * 4));
    
    // Free the memory allocated for the header
    ipv4_header_destroy(header);
    
    return packet;
}


/*
* Fonction: ipv4_header_create_from_string
* Description: Création d'un en-tête IPv4 à partir d'une chaîne de caractères
* Paramètres:
*   - string: Chaîne de caractères représentant l'en-tête
* Retour: Pointeur vers l'en-tête créé
*/
struct ipv4_header *ipv4_header_create_from_string(char *string) {
    uint32_t length = 0;
    uint8_t *binary = malloc(strlen(string) * sizeof(uint8_t));
    if (binary == NULL) {
        perror("Erreur d'allocation de mémoire pour la représentation binaire de l'en-tête");
        return NULL;
    }
    for (uint32_t i = 0; i < strlen(string); i++) {
        if (string[i] == '0') {
            binary[length] = 0x00;
            length++;
        } else if (string[i] == '1') {
            binary[length] = 0x01;
            length++;
        }
    }
    struct ipv4_header *header = ipv4_header_create_from_binary(binary);
    free(binary);
    return header;
}

/*
* Fonction: ipv4_packet_create_from_string
* Description: Création d'un paquet IPv4 à partir d'une chaîne de caractères
* Paramètres:
*   - string: Chaîne de caractères représentant le paquet
* Retour: Pointeur vers le paquet créé
*/
struct ipv4_packet *ipv4_packet_create_from_string(char *string) {
    uint32_t length = 0;
    uint8_t *binary = malloc(strlen(string) * sizeof(uint8_t));
    if (binary == NULL) {
        perror("Erreur d'allocation de mémoire pour la représentation binaire du paquet");
        return NULL;
    }
    for (uint32_t i = 0; i < strlen(string); i++) {
        if (string[i] == '0') {
            binary[length] = 0x00;
            length++;
        } else if (string[i] == '1') {
            binary[length] = 0x01;
            length++;
        }
    }
    struct ipv4_packet *packet = ipv4_packet_create_from_binary(binary, length);
    free(binary);
    return packet;
}


/*
* Fonction: binaryToHex
* Description: Conversion d'une représentation binaire en une représentation hexadécimale
* Paramètres:
*   - binary: Représentation binaire
*   - length: Longueur de la représentation binaire
* Retour: Chaîne de caractères représentant la représentation hexadécimale
*/
char* binaryToHex(const uint8_t *binary, size_t length) {
    // Each byte of binary data is represented by two hexadecimal characters.
    // Additionally, we need one more character for the null terminator.
    char *hexString = (char *)malloc(length * 2 + 1);
    
    if (hexString == NULL) {
        return NULL; // Memory allocation failed
    }
    
    for (size_t i = 0; i < length; i++) {
        // Convert each byte to its hexadecimal representation.
        // The %02X format specifier is used to ensure that each byte is represented by two characters.
        sprintf(&hexString[i * 2], "%02X", binary[i]);
    }
    
    hexString[length * 2] = '\0'; // Null-terminate the hexadecimal string
    return hexString;
}

/*
* Fonction: hexToBinary
* Description: Conversion d'une représentation hexadécimale en une représentation binaire
* Paramètres:
*   - hexString: Représentation hexadécimale
*   - binaryLength: Pointeur vers la longueur de la représentation binaire
* Retour: Représentation binaire
*/
uint8_t* hexToBinary(const char *hexString, size_t *binaryLength) {
    // Each byte in the binary data corresponds to two hexadecimal characters.
    *binaryLength = strlen(hexString) / 2;
    uint8_t *binary = (uint8_t *)malloc(*binaryLength);
    
    if (binary == NULL) {
        return NULL; // Memory allocation failed
    }
    
    for (size_t i = 0; i < *binaryLength; i++) {
        // Convert each pair of hexadecimal characters to a byte and store it in the binary array.
        sscanf(&hexString[i * 2], "%2hhx", &binary[i]);
    }
    
    return binary;
}

/*
* Fonction: decimalToBinary
* Description: Conversion d'un entier en une représentation binaire
* Paramètres:
*   - value: Entier à convertir
*   - bits: Nombre de bits à convertir
* Retour: Représentation binaire
*/
uint8_t* decimalToBinary(uint32_t value, int bits) {
    uint8_t *binary = (uint8_t *)malloc(bits);
    
    if (binary == NULL) {
        return NULL; // Memory allocation failed
    }
    
    for (int i = bits - 1; i >= 0; i--) {
        binary[i] = (value >> i) & 1;
    }
    
    return binary;
}

/*
* Fonction: binaryToDecimal
* Description: Conversion d'une représentation binaire en un entier
* Paramètres:
*   - binary: Représentation binaire
*   - bits: Nombre de bits à convertir
* Retour: Entier
*/
uint32_t binaryToDecimal(const uint8_t *binary, int bits) {
    uint32_t value = 0;
    
    for (int i = bits - 1; i >= 0; i--) {
        value |= binary[i] << i;
    }
    
    return value;
}

/*
* Fonction: decimalToHex
* Description: Conversion d'un entier en une représentation hexadécimale
* Paramètres:
*   - value: Entier à convertir
*   - bytes: Nombre d'octets à convertir
* Retour: Chaîne de caractères représentant la représentation hexadécimale
*/
char* decimalToHex(uint32_t value, int bytes) {
    // Each byte of binary data is represented by two hexadecimal characters.
    // Additionally, we need one more character for the null terminator.
    char *hexString = (char *)malloc(bytes * 2 + 1);
    
    if (hexString == NULL) {
        return NULL; // Memory allocation failed
    }
    
    for (int i = bytes - 1; i >= 0; i--) {
        // Convert each byte to its hexadecimal representation.
        // The %02X format specifier is used to ensure that each byte is represented by two characters.
        sprintf(&hexString[(bytes - 1 - i) * 2], "%02X", (value >> (i * 8)) & 0xFF);
    }
    
    hexString[bytes * 2] = '\0'; // Null-terminate the hexadecimal string
    return hexString;
}

/*
* Fonction: hexToDecimal
* Description: Conversion d'une représentation hexadécimale en un entier
* Paramètres:
*   - hexString: Représentation hexadécimale
*   - bytes: Nombre d'octets à convertir
* Retour: Entier
*/
uint32_t hexToDecimal(const char *hexString, int bytes) {
    uint32_t value = 0;
    
    for (int i = bytes - 1; i >= 0; i--) {
        // Convert each pair of hexadecimal characters to a byte and store it in the binary array.
        sscanf(&hexString[(bytes - 1 - i) * 2], "%2hhx", &value);
    }
    
    return value;
}

/*
* Fonction: print_border
* Description: Affichage d'une bordure
* Paramètres:
*   - length: Longueur de la bordure
* Retour: Rien
*/
void print_border(int length) {
    printf("+");
    for (int i = 0; i < length; i++) {
        printf("-");
    }
    printf("+\n");
}






int main() {
    struct ipv4_header *header = ipv4_header_create(4, 5, 0, 20, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0);
    ipv4_header_print(header);
    ipv4_header_print_binary(header);

    uint8_t *data = malloc(4 * sizeof(uint8_t));
    if (data == NULL) {
        perror("Erreur d'allocation de mémoire pour les données du paquet");
        ipv4_header_destroy(header);
        return 1;
    }
    data[0] = 0x00;
    data[1] = 0x01;
    data[2] = 0x02;
    data[3] = 0x03;

    struct ipv4_packet *packet = ipv4_packet_create(header, data, 4);
    ipv4_packet_print(packet);
    ipv4_packet_destroy(packet);

    ipv4_header_destroy(header);

    /* 45 00
    0010 00 84 25 05 00 00 FF 11 86 3A CO 09 C8 0A CO 09
    0020 08 0B 04 0A 05 6B 00 70 00 00 24 13 F2 13 00 00
    0030 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0040 00 00 00 00 00 01 00 00 00 45 74 6F 75 74 61 69
    0050 6E 3A 56 53 43 49 77 76 33 45 4B 4E 6B 73 32 3А
    0060 33 30 31 38 ЗА 33 30 31 ЗА 53 43 49 45 4E 54 49
    0070 46 3A 2F 75 73 72 2F 75 34 2F 6C 61 62 6F 2F 74
    0080 6F 75 74 61 69 6E 3A 2F 62 69 6E 2F 63 73 68 00
    0090 00 00
    */
     const char *hexString = "4500008425050000FF11863AC009C80AC009080B040A056B007000002413F213"
                            "0001000000000000000000000000000000000100000045746F757461696E3A56"
                            "534349777633454B4E6B73323AA33303138ZA333031ZA534349454E5449463A2F"
                            "7573722F75342F6C61626F2F746F757461696E3A2F62696E2F6373680000";
    struct ipv4_packet *packet2 = ipv4_packet_create_from_hexadecimal(hexString, strlen(hexString));
    ipv4_packet_print(packet2);
    



    return 0;
}





