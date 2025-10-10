# PROY2_PARALELA

Proyecto 2 de programación paralela, aplicación de desencriptación con fuerza bruta

## Dependencias

### Ubuntu-Debian

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

### Arch

```bash
sudo pacman -S openssl
```

## Instrucciones de compilación y ejecución

### Compilación base de bruteforce.c

```bash
mpicc -o bruteforce bruteforce.c -lcrypto
```

### Encriptar texto en plain_text.txt

```bash
./bruteforce encrypt 
```

### Desencriptar el texto usando la key

```bas
mpiexec -n 4 ./bruteforce
```
