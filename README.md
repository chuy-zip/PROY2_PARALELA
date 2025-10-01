# PROY2_PARALELA
Proyecto 2 de programación paralela, aplicación de desencriptación con fuerza bruta

### Dependencias

#### Ubuntu-Debian

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

## Ejecución base de bruteforce.c
mpicc -o bruteforce bruteforce.c -lcrypto