mod aes;
mod secrets;
mod challenge;

#[macro_use]
extern crate serde_big_array;
#[macro_use]
extern crate arrayref;


//Battery service
pub enum BatteryService {
    IdxBatterySvc,
    IdxCharBatteryLevel,
    IdxCharBatteryLevelVal,
    IdxCharBatteryLevelCfg,
    BatteryLastIdx
}

//LED/BUTTON service
pub enum LEDButtonService {
    IdxLedButtonSvc,
    IdxCharLed,
    IdxCharLedVal,
    IdxCharButton,
    IdxCharButtonVal,
    IdxCharButtonCfg,
    IdxCharUnknown,
    IdxCharUnknownVal,
    IdxCharUpdateRequest,
    IdxCharUpdateRequestVal,
    IdxCharFwVersion,
    IdxCharFwVersionVal,
    LedButtonLastIdx
}

//Certificate service
pub enum CertificateService {
    IdxCertSvc,
    IdxCharCentralToSfida,
    IdxCharCentralToSfidaVal,
    IdxCharSfidaCommands,
    IdxCharSfidaCommandsVal,
    IdxCharSfidaCommandsCfg,
    IdxCharSfidaToCentral,
    IdxCharSfidaToCentralVal,
    CertLastIdx
}