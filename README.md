# Pokemon Go Pro on Rust #

## Custom AES & Challenges ##

Implements main challenges and custom AES-CTR as seen in 
[PGPEmu](https://github.com/yohanes/pgpemu), detailed in 
[Reverse Engineering Pokémon GO Plus](https://tinyhack.com/2018/11/21/reverse-engineering-pokemon-go-plus/).

## Bluetooth LE & GATT ##

Bluetooth development is blocked on a good BLE peripheral emulation
crate.

### Armv7_hf support ###

Armv7_hf support is included for development in Raspberry Pi 3 devices
through [Cross Compile Script](xcompile.ps1) via Docker.