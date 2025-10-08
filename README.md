# PROY2_PARALELA
Proyecto 2 de programación paralela, aplicación de desencriptación con fuerza bruta

### Dependencias

#### Ubuntu-Debian

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

#### Arch
```bash
sudo pacman -S openssl
```

## Compilación base de bruteforce.c
mpicc -o bruteforce bruteforce.c -lcrypto

### Encriptar texto en plain_text.txt
./bruteforce encrypt 

### Desncriptar el texto usando la key
mpiexec -n 4 ./bruteforce
