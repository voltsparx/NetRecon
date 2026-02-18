def display(results):
    print(f"\nScan Results for {results['target']}")
    print("PORT\tSERVICE")
    for port, service in results["open_ports"]:
        print(f"{port}\t{service}")
    print(f"\nDetected OS: {results['os']}")
