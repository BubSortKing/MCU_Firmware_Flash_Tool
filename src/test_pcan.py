"""Quick PCAN hardware test — DiagnosticSessionControl to ECU."""

from canbus.pcan_driver import PCANDriver

driver = PCANDriver()
driver.connect()

# DiagnosticSessionControl (0x10), Default Session (0x01)
driver.send(0x7A2, b'\x02\x10\x01')

msg = driver.receive_filtered(0x7AA, timeout=2.0)
if msg:
    print(f"Response: [0x{msg.arbitration_id:03X}] {bytes(msg.data).hex(' ')}")
else:
    print("No response (timeout)")

driver.disconnect()
print("Done")
