
#  Device Authentication

# PART 1: DATA STRUCTURE (Trusted Registry)

# List of all TRUSTED devices
# This is the REGISTRY!
trusted_devices = [
    {
        "device_id": "DEVICE_001",
        "device_name": "Ahmed's Heart Monitor",
        "patient_name": "Ahmed Ali",
        "status": "ACTIVE"
    },
    {
        "device_id": "DEVICE_002",
        "device_name": "Sara's BP Monitor",
        "patient_name": "Sara Khan",
        "status": "ACTIVE"
    },
    {
        "device_id": "DEVICE_003",
        "device_name": "Anoop's Heart Monitor",
        "patient_name": "Anoop Menon",
        "status": "ACTIVE"
    },
    {
        "device_id": "DEVICE_004",
        "device_name": "Benzen's pacemakers ",
        "patient_name": "Benzen John",
        "status": "ACTIVE"
    },
]



# PART 2: FUNCTION 1 (Register Device)


def register_device(device_id, device_name, patient_name):
    
    print(f"\n Registering Device: {device_id}")
    
    new_device = {
        "device_id": device_id,
        "device_name": device_name,
        "patient_name": patient_name,
        "status": "ACTIVE"
    }
    
    trusted_devices.append(new_device)
    
    print(f"   Device {device_id} registered successfully!")
    print(f"   Name: {device_name}")
    print(f"   Patient: {patient_name}")
    print(f"   Status: ACTIVE")



# PART 3: FUNCTION 2 (Check if Trusted)


def is_device_trusted(device_id):
   
    print(f"\n Checking Device: {device_id}")
    
    # Search through registry
    for device in trusted_devices:
        if device["device_id"] == device_id:
            print(f"   Found in registry ")
            print(f"   Status: {device['status']}")
            
            if device["status"] == "ACTIVE":
                print(f"   Result: TRUSTED! ")
                return True
            else:
                print(f"   Result: NOT ACTIVE! ")
                return False
    
    # Device not found
    print(f"   NOT FOUND in registry ")
    print(f"   Result: NOT TRUSTED! ")
    return False


# PART 4: DEMO

if __name__ == "__main__":
    
    print("="*70)
    print("WEEK 1: DEVICE AUTHENTICATION MODULE")
    print("TRUSTED REGISTRY AND CHECK LOGIC")
    print("="*70)
    
    # Example 1: Show current trusted devices
    print("\n" + "="*70)
    print("Current Trusted Devices:")
    print("="*70)
    
    for device in trusted_devices:
        print(f"  {device['device_id']}: {device['device_name']} ({device['status']})")
    
    # Example 2: Register new device
    print("\n" + "="*70)
    print("EXAMPLE 1: Register New Device")
    print("="*70)
    
    register_device("DEVICE_005", "John's Glucose Monitor", "John Smith")
    
    # Example 3: Check trusted device
    print("\n" + "="*70)
    print("EXAMPLE 2: Check Valid Device")
    print("="*70)
    
    result = is_device_trusted("DEVICE_001")
    print(f"Final Result: {result}")
    
    # Example 4: Check untrusted device
    print("\n" + "="*70)
    print("EXAMPLE 3: Check Invalid Device")
    print("="*70)
    
    result = is_device_trusted("DEVICE_999")
    print(f"Final Result: {result}")
    
    # Show final registry
    print("\n" + "="*70)
    print("Final Trusted Devices:")
    print("="*70)
    
    for device in trusted_devices:
        print(f"  {device['device_id']}: {device['device_name']} ({device['status']})")
  