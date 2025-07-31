try:
    moduleError = False
    importedModules = ['os', 'psutil', 'sys', 'ids']
    successfulModules = []
    import os
    successfulModules.append('os')
    import psutil
    successfulModules.append('psutil')
    import sys
    successfulModules.append('sys')
    import intrusion_detection_system
    successfulModules.append('ids')
    print('All modules imported correctly.')
except:
    for module in importedModules:
        if module == 'ids':
            print('[!] Module "' + module + '" is missing required dependencies to be installed, or requires root/sudo permissions.')
            moduleError = True
        elif module not in successfulModules:
            print('[!] Module "' + module + '" is not installed on the device.')
            moduleError = True

class DetermineSystemRequirements:

    def __init__(self):
        print(self.determineOperatingEnv())
        print(self.determineHardware())
        print(self.determineStorage())

    def determineOperatingEnv(self): # Determining operating environment. (Current Operating System and Current Solution Version)
        currentVersion = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
        operatingSystem = os.name
        
        if operatingSystem == 'nt': # Detected Windows Operating System
            return 'Detected Windows operating system, running ' + currentVersion + ' of SIEM solution.'
        elif operatingSystem == 'posix': # Detected Linux Operating System
            return 'Detected Linux operating system, running ' + currentVersion + ' of SIEM solution.'
        else:
            return '[!] Cannot detect operating system, running ' + currentVersion + ' of SIEM solution. Errors may occur.'
    
    def determineHardware(self): # Determing hardware requirements. (Amount of CPUS, )
        cpuCount = os.cpu_count()
        totalMemory = round(psutil.virtual_memory().total / 1073741824)
        
        if cpuCount is None or totalMemory == 0:
            return '[!] Cannot determine CPU count or total Ram. Errors may occur.'
        elif cpuCount < 4 or totalMemory < 4:
            return '[!] Detected less than 4 CPU cores or RAM installed. Errors may occur.'
        else:
            return 'Detected ' + str(cpuCount) + ' CPU cores and ' + str(totalMemory) + ' GB of RAM.'
    
    def determineStorage(self):
        disk = round(psutil.disk_usage('/').total / (1024.0 ** 3))
        if disk < 256:
            return '[!] Detected hard disk size of ' + str(disk) + ' GB, lower than minimum specs. Errors may occur.'
        else:
            return 'Detected ' + str(disk) + ' GB in hard disk.'

if __name__ == '__main__':
    if moduleError == True:
        print('[!] Exiting program...')
        sys.exit()
    DSR = DetermineSystemRequirements()
    IDS = intrusion_detection_system.DataAggregation()
