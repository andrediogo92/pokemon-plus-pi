use blurz::{BluetoothAdapter, BluetoothDevice, BluetoothSession};

fn main() {
    let session: BluetoothSession = BluetoothSession::create_session(Option::None).unwrap();
    let adapter: BluetoothAdapter = BluetoothAdapter::init(&session).unwrap();
    let device: BluetoothDevice = adapter.get_first_device().unwrap();
    println!("{:?}", device);
}
