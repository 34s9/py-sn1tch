""" 'Dependency Checking Documentation'
I used try and except statements as when a python module is not installed it returns an error. This will therefore catch the error allowing for the program to continue running.
The 'moduleError' variable is a boolean as it is the best way to show whether an error has occured, as it only uses True or False therefore being efficient. This is seen as a 'flag', where being True means a module is not installed. And False being all modules are properly installed.
The 'importedModules' array contains a list of all modules that are required for the program to launch in this file. I used a array as it is the best way to store a list of strings, and because of its simple and easy indexing. Therefore allowing me to easily index all possible names of modules.
The 'successfulModules' array contains a list of all modules that have been successfully imported into the program. I used an array as it is the best way to store a list of strings, and because of its simple and easy indexing. Therefore allowing me to easily index all possible names of modules.
Each 'import' statement imports a required dependency for the program to work. I decided to use import as it is the most efficient way to import methods from other files.
After each import I append the name of the module into successfulModules. I used append as it is the only way to append strings into a list. I used the module name as a string as it is the only way to store actual characters aside from their unicode.
I then print All modules imported correctly. To alert the user that no problems were encountered during dependency checking.

If a module is ever throwing an error when importing, the module was not installed on the device.
We then check every module that was supposed to be imported. Using a for loop as it is the easiest way to iterate across a array.
If the module is the intrusion_detection_system module...
We alert the user that the UPDATE HERE file is missing required dependencies, or alternatively requires root/sudo permission (if on linux).
We then make 'moduleError' equal to True. So the program will not start.
If the module is not installed...
We alert the user that the module is not installed on the device.
And then make 'moduleError' equal to True to stop the program from running.
"""

try:
    moduleError = False
    importedModules = ['os', 'psutil', 'sys', 'scapy', 'tkinter', 'pillow', 'urllib']
    successfulModules = []
    import os
    successfulModules.append('os')
    import psutil
    successfulModules.append('psutil')
    import sys
    successfulModules.append('sys')
    from scapy.all import sniff, wrpcap
    successfulModules.append('scapy')
    import tkinter as tk
    from tkinter import *
    import tkinter.font
    successfulModules.append('tkinter')
    from PIL import Image, ImageTk
    successfulModules.append('pillow')
    from urllib import request
    successfulModules.append('urllib')
    print('All modules imported correctly.')
except:
    for module in importedModules:
        if module == 'dataAgg':
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

class DataAggregation:
    def __init__(self, resetCount):
        self.resetCount = resetCount
        self.amountPassed = 0
        self.fileCount = 1
        self.packets = []

    def packetCallback(self, packet):
        self.packets.append(packet)

    def sniffPacket(self):
        sniff(prn = self.packetCallback, count = self.resetCount)
        self.amountPassed += self.resetCount
    
    def writePCAP(self):
        wrpcap('logsPCAP/' + str(self.fileCount) + '.pcap', self.packets)

    def loopIterated(self):
        self.fileCount += 1

    def resetLogs(self):
        pass
        # Insert code to delete logsPCAP files here.

## FRONT END ##

class PageManager(tk.Tk):
    def __init__(self, screenName = None, baseName = None, className = "Tk", useTk = True, sync = False, use = None):
        super().__init__(screenName, baseName, className, useTk, sync, use)

        self.title('py-sn1tch')

        container = tk.Frame(self, height = 400, width = 600)
        container.pack(side = 'top', fill = 'both', expand = True)

        self.pages = {}

        for p in (MainMenu, CapturePage, LogsPage, AlertsPage, BenchmarkPage, SettingsPage):
            page = p(container, self)

            self.pages[p] = page
            page.grid(row = 0, column = 0, sticky = 'nsew')
        
        self.raisePage(MainMenu)
    
    def raisePage(self, cont):
        page = self.pages[cont]
        page.tkraise()

class MainMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        menuFont = tkinter.font.Font(family = 'Adawaita Sans', size = 16, weight = 'bold')
        textFont = tkinter.font.Font(family = 'Adawaita Sans', size = 12, weight = 'normal')

        MainMenu.configure(self, background = 'white')

        #tempIcon = PhotoImage(file = 'Textures/placeholder.png')
        logsButtonTexture = PhotoImage(file = 'Textures/logsButtonTexture.png')
        alertsButtonTexture = PhotoImage(file = 'Textures/alertsButtonTexture.png')
        benchmarkButtonTexture = PhotoImage(file = 'Textures/benchmarkButtonTexture.png')
        settingsButtonTexture = PhotoImage(file = 'Textures/settingsButtonTexture.png')
        networkOfflineTexture = PhotoImage(file = 'Textures/networkOffline.png')
        networkOnlineTexture = PhotoImage(file = 'Textures/networkOnline.png')

        self.networkOfflineLabel = tk.Label(self, image = networkOfflineTexture, width = 48, height = 48, background = 'white')
        self.networkOfflineLabel.image = networkOfflineTexture
        self.networkOfflineLabel.grid(row = 1, column = 1)

        self.networkOnlineLabel = tk.Label(self, image = networkOnlineTexture, width = 48, height = 48, background = 'white')
        self.networkOnlineLabel.image = networkOnlineTexture
        self.networkOnlineLabel.grid(row = 1, column = 1)

        self.networkTextLabel = tk.Label(self, background = 'white', text = 'Network Disabled', font = textFont)
        self.networkTextLabel.grid(row = 1, column = 2)

        refreshButton = tk.Button(self, text = 'Refresh Network', 
                                  font = textFont, 
                                  highlightthickness = 0,
                                  background = 'white',
                                  relief = 'raised',
                                  command = self.refreshNetwork)
        refreshButton.grid(row = 1, column = 3)

        logsButton = tk.Button(self, image = logsButtonTexture, 
                               highlightthickness = 0, 
                               background = 'white', 
                               width = 200, height = 200, 
                               relief = 'flat', 
                               command=lambda: controller.raisePage(CapturePage))
        
        logsButton.image = logsButtonTexture
        logsButton.grid(row = 2, column = 2, padx = 10, pady = 10)

        logsLabel = tk.Label(self, text = 'Logs', font = menuFont, background = 'white')
        logsLabel.grid(row = 3, column = 2, padx = 10)

        alertsButton = tk.Button(self, image = alertsButtonTexture, 
                                 highlightthickness = 0, 
                                 background = 'white', 
                                 width = 200, height = 200, 
                                 relief = 'flat', 
                                 command=lambda: controller.raisePage(AlertsPage))
        
        alertsButton.image = alertsButtonTexture
        alertsButton.grid(row = 2, column = 3, padx = 10, pady = 10)

        alertsLabel = tk.Label(self, text = 'Alerts', font = menuFont, background = 'white')
        alertsLabel.grid(row = 3, column = 3, padx = 10)

        benchmarkButton = tk.Button(self, image = benchmarkButtonTexture, 
                                    highlightthickness = 0, 
                                    background = 'white', 
                                    width = 200, height = 200, 
                                    relief = 'flat', 
                                    command=lambda: controller.raisePage(BenchmarkPage))
        
        benchmarkButton.image = benchmarkButtonTexture
        benchmarkButton.grid(row = 2, column = 4, padx = 10, pady = 10)

        benchmarkLabel = tk.Label(self, text = 'Benchmark Device', font = menuFont, background = 'white')
        benchmarkLabel.grid(row = 3, column = 4, padx = 10)

        settingsButton = tk.Button(self, image = settingsButtonTexture, 
                                   highlightthickness = 0, 
                                   background = 'white', 
                                   width = 200, height = 200, 
                                   relief = 'flat', 
                                   command=lambda: controller.raisePage(SettingsPage))
        
        settingsButton.image = settingsButtonTexture
        settingsButton.grid(row = 2, column = 5, padx = 10, pady = 10)

        settingsLabel = tk.Label(self, text = 'Settings', font = menuFont, background = 'white')
        settingsLabel.grid(row = 3, column = 5, padx = 10)

        self.refreshNetwork()

    def checkConnection(self):
        try:
            request.urlopen('https://8.8.8.8', timeout = 1) # Maps to google DNS lookup.
            return True
        except request.URLError as err:
            return False

    def refreshNetwork(self):
        self.networkOfflineLabel.grid_forget()
        self.networkOnlineLabel.grid_forget()

        if self.checkConnection() == True:
            self.networkOnlineLabel.grid(row = 1, column = 1)
            self.networkTextLabel.config(text = 'Network Enabled')
        else:
            self.networkOfflineLabel.grid(row = 1, column = 1)
            self.networkTextLabel.config(text = 'Network Disabled')


class CapturePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        CapturePage.configure(self, background = 'white')

        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

class LogsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

class AlertsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

class BenchmarkPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

class SettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

if __name__ == '__main__':
    if moduleError == True:
        print('[!] Exiting program...')
        try:
            sys.exit()
        except:
            exit()
    DSR = DetermineSystemRequirements()
    DA = DataAggregation(resetCount=120)

    'Start Front End'
    main = PageManager()
    main.mainloop()

    'Using OS.system to run terminal command to analyze file.'
    #os.system("python packetAnalysis.py --pcap-file /run/media/matthew/'USB DRIVE'/'~ VCE - Software Development/Folio/DEVELOPMENT'/version_0.0.11/logsPCAP/2.pcap")

    'Example of possible packet loop.'

    # while True:
    #     try:
    #         # Insert threading here.

    #         DA.sniffPacket()
    #         DA.writePCAP()
    #         DA.loopIterated()

    #         # Insert code to update tkinter display...

    #     except KeyboardInterrupt:
    #         print('Stopping dataAggregation...')
    #         break
    #     except PermissionError:
    #         print('Please run the program using sudo and python -E flag.')
    #         break
    #     except:
    #         print('Error has occurred')
    #         break
