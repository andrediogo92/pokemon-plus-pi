param([string]$command="build")
$version="1.39.0"

# Ensure Rust and the ARM toolchain are installed.
If (-Not (Get-Command docker -ErrorAction SilentlyContinue)) {
    'It looks like Docker is not installed on your system.' | Write-Error
    Exit
}

If (-Not (docker images | Select-String "ragnaroek/rust-raspberry(\s+)$version" -ErrorAction SilentlyContinue)) {
    'Image not detected, attempt to pull' | Write-Debug
    docker pull "ragnaroek/rust-raspberry:$version"
}

docker run `
    -v D:\Andre\Documents\RaspberryPi\BluetoothPGP:/home/cross/project `
    -v D:\Andre\Documents\RaspberryPi\BluetoothPGP\deb-deps:/home/cross/deb-deps `
    -v C:\Users\Andre\.cargo\registry:/home/cross/.cargo/registry ragnaroek/rust-raspberry:1.39.0 `
    $command