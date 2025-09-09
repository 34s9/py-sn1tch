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
If the module is the dataAggregation.py...
We alert the user that the dataAggregation file is missing required dependencies, or alternatively requires root/sudo permission (if on linux).
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
    from os.path import isfile, join
    successfulModules.append('os')
    import psutil
    successfulModules.append('psutil')
    import sys
    successfulModules.append('sys')
    from scapy.all import sniff, wrpcap
    successfulModules.append('scapy')
    import tkinter as tk
    from tkinter import filedialog, ttk, messagebox
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

"""
DETERMINE SYSTEM REQUIREMENTS DOCUMENTATION

I decided to 
"""

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

## FRONT END ##

class PageManager(tk.Tk):
    def __init__(self, screenName = None, baseName = None, className = "Tk", useTk = True, sync = False, use = None):
        super().__init__(screenName, baseName, className, useTk, sync, use)

        self.title('py-sn1tch')

        container = tk.Frame(self, height = 400, width = 600)
        container.pack(side = 'top', fill = 'both', expand = True)

        self.pages = {}

        for p in (MainMenu, LogsPage, AlertsPage, BenchmarkPage, CapturePage, SettingsPage):
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

        logsButtonTexture = PhotoImage(file = 'Textures/logsButtonTexture.png')
        alertsButtonTexture = PhotoImage(file = 'Textures/alertsButtonTexture.png')
        benchmarkButtonTexture = PhotoImage(file = 'Textures/benchmarkButtonTexture.png')
        captureButtonTexture = PhotoImage(file = 'Textures/captureButtonTexture.png')
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
                               command=lambda: controller.raisePage(LogsPage))
        
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

        captureButton = tk.Button(self, image = captureButtonTexture, 
                                   highlightthickness = 0, 
                                   background = 'white', 
                                   width = 200, height = 200, 
                                   relief = 'flat', 
                                   command=lambda: controller.raisePage(CapturePage))
        
        captureButton.image = captureButtonTexture
        captureButton.grid(row = 2, column = 5, padx = 10, pady = 10)

        captureLabel = tk.Label(self, text = 'Capture', font = menuFont, background = 'white')
        captureLabel.grid(row = 3, column = 5, padx = 10)

        settingsButton = tk.Button(self, image = settingsButtonTexture, 
                                   highlightthickness = 0, 
                                   background = 'white', 
                                   width = 200, height = 200, 
                                   relief = 'flat', 
                                   command=lambda: controller.raisePage(SettingsPage))
        
        settingsButton.image = settingsButtonTexture
        settingsButton.grid(row = 2, column = 6, padx = 10, pady = 10)

        settingsLabel = tk.Label(self, text = 'Settings', font = menuFont, background = 'white')
        settingsLabel.grid(row = 3, column = 6, padx = 10)

        self.refreshNetwork()

    def checkConnection(self):
        global networkEnabled
        try:
            request.urlopen('https://8.8.8.8', timeout = 1) # Maps to google DNS lookup.
            networkEnabled = True
            return True
        except request.URLError as err:
            networkEnabled = False
            return False

    def refreshNetwork(self):
        try:
            self.networkOfflineLabel.grid_forget()
            self.networkOnlineLabel.grid_forget()

            if self.checkConnection() == True:
                self.networkOnlineLabel.grid(row = 1, column = 1)
                self.networkTextLabel.config(text = 'Network Enabled')
            else:
                self.networkOfflineLabel.grid(row = 1, column = 1)
                self.networkTextLabel.config(text = 'Network Disabled')
        except:
            pass

class LogsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        LogsPage.configure(self, background = 'white')

        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')
        searchButtonTexture = PhotoImage(file = 'Textures/searchTexture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

        fileSelectButton = tk.Button(self, text = 'Select PCAP File',
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.selectPCAP)
        fileSelectButton.grid(row = 1, column = 2)

        readButton = tk.Button(self, text = 'Read File',
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.readPCAP)
        readButton.grid(row = 1, column = 3)

        self.packetTree = ttk.Treeview(self, columns = ('Destination', 'Protocol', 'Information', 'Time'))

        self.packetTree.heading('#0', text = 'Source')
        self.packetTree.heading('Destination', text = 'Destination')
        self.packetTree.heading('Protocol', text = 'Protocol')
        self.packetTree.heading('Information', text = 'Information')
        self.packetTree.heading('Time', text = 'Time')

        verticalScrollBar = ttk.Scrollbar(self, orient = tk.VERTICAL, command = self.packetTree.yview)
        self.packetTree.configure(yscrollcommand = verticalScrollBar.set)

        self.packetTree.grid(row = 2, column = 2, )
        verticalScrollBar.grid(row = 2, column = 3, sticky = 'ns')

        self.searchBar = ttk.Entry(self)
        self.searchBar.grid(row = 1, column = 4)

        searchButton = tk.Button(self, image = searchButtonTexture,
                                 width = 25, height = 25,
                                 background = 'white',
                                 relief = 'flat',
                                 highlightthickness = 0,
                                 command = lambda: self.searchTreeview(self.searchBar.get()))
        searchButton.image = searchButtonTexture
        searchButton.grid(row = 1, column = 5)

    def selectPCAP(self):
        try:
            global filePath
            filePath = filedialog.askopenfilename(title = 'Select PCAP file', filetypes = [('PCAP File', '*.pcap')])
        except:
            pass
    
    def readPCAP(self):
        try:
            if (filePath.split('/')[-1])[1:] == '.pcap':
                command = str('python packetAnalysis.py --pcap-file ' + filePath)
                try:
                    os.system(command)

                    global result
                    result = os.popen(command).read()
                    result = result.split('py-sn1tchRequireKeyword')
                    result = eval(result[-1])
                    
                    global indexedValues
                    indexedValues = {}

                    for packet in result.keys():
                        insert = self.packetTree.insert('', tk.END, text = str(packet[0]), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time']))))
                        indexedValues[insert] = packet
                    self.packetTree.bind('<Double-1>', self.onDoubleClick)

                except:
                    print('[!] Ensure all your folder names in the directory has no spaces.')

            else:
                print('[!] Ensure you have selected a PCAP file with the extension .pcap')
        except:
            pass
    
    def onDoubleClick(self, event):
        try:
            item = self.packetTree.selection()[0]
            win = tk.Toplevel()
            win.wm_title('Extra Details for packet: ' + str(self.packetTree.item(item, 'text')))
            win.configure(background = 'white')
            index = indexedValues[item]

            source = index[0]
            sport = index[1]
            destination = index[2]
            dport = index[3]
            startTime = result[index]['start_time']
            lastSeen = result[index]['last_seen']
            numOfPackets = result[index]['packets']
            bytes = result[index]['bytes']
            protocol = result[index]['protocol_name']
            anomalies = result[index]['flagged_anomalies']

            sourceLabel = tk.Label(win, text = 'Source: ' + str(source), background = 'white')
            sportLabel = tk.Label(win, text = 'Source Port: ' + str(sport), background = 'white')
            destinationLabel = tk.Label(win, text = 'Destination: ' + str(destination), background = 'white')
            dportLabel = tk.Label(win, text = 'Destination Port: ' + str(dport), background = 'white')
            startTimeLabel = tk.Label(win, text = 'Start Time: ' + str(startTime), background = 'white')
            lastSeenLabel = tk.Label(win, text = 'Last Seen: ' + str(lastSeen), background = 'white')
            numOfPacketsLabel = tk.Label(win, text = '# of Packets: ' + str(numOfPackets), background = 'white')
            bytesLabel = tk.Label(win, text = 'Bytes: ' + str(bytes), background = 'white')
            protocolLabel = tk.Label(win, text = 'Protocol: ' + str(protocol), background = 'white')
            anomaliesLabel = tk.Label(win, text = 'Anomalies Detected: ' + str(anomalies), background = 'white')

            sourceLabel.grid(row = 1, column = 1)
            sportLabel.grid(row = 2, column = 1)
            destinationLabel.grid(row = 3, column = 1)
            dportLabel.grid(row = 4, column = 1)
            startTimeLabel.grid(row = 5, column = 1)
            lastSeenLabel.grid(row = 6, column = 1)
            numOfPacketsLabel.grid(row = 7, column = 1)
            bytesLabel.grid(row = 8, column = 1)
            protocolLabel.grid(row = 9, column = 1)
            anomaliesLabel.grid(row = 10, column = 1)

            closeButton = tk.Button(win, text = 'Close', background = 'white', relief = 'raised', highlightthickness = 0, command = win.destroy)
            closeButton.grid(row = 11, column = 1)

        except:
            pass
    
    def searchTreeview(self, query):
        try:
            items = self.packetTree.get_children()
            for item in items:
                if query.lower() in str(self.packetTree.item(item)['values']).lower():
                    self.packetTree.selection_set(item)
                    self.packetTree.focus(item)
                    return
            messagebox.showinfo('Search', f'No results found for "{query}".')
        except:
            pass


class AlertsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        AlertsPage.configure(self, background = 'white')

        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')
        searchButtonTexture = PhotoImage(file = 'Textures/searchTexture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

        fileSelectButton = tk.Button(self, text = 'Select PCAP File',
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.selectPCAP)
        fileSelectButton.grid(row = 1, column = 2)

        analyzeButton = tk.Button(self, text = 'Analyze File',
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.analyzePCAP)
        analyzeButton.grid(row = 1, column = 3)

        self.packetTree = ttk.Treeview(self, columns = ('Destination', 'Protocol', 'Information', 'Time'))

        self.packetTree.heading('#0', text = 'Source')
        self.packetTree.heading('Destination', text = 'Destination')
        self.packetTree.heading('Protocol', text = 'Protocol')
        self.packetTree.heading('Information', text = 'Information')
        self.packetTree.heading('Time', text = 'Time')

        verticalScrollBar = ttk.Scrollbar(self, orient = tk.VERTICAL, command = self.packetTree.yview)
        self.packetTree.configure(yscrollcommand = verticalScrollBar.set)

        self.packetTree.grid(row = 2, column = 2, )
        verticalScrollBar.grid(row = 2, column = 3, sticky = 'ns')

        self.searchBar = ttk.Entry(self)
        self.searchBar.grid(row = 1, column = 4)

        searchButton = tk.Button(self, image = searchButtonTexture,
                                 width = 25, height = 25,
                                 background = 'white',
                                 relief = 'flat',
                                 highlightthickness = 0,
                                 command = lambda: self.searchTreeview(self.searchBar.get()))
        searchButton.image = searchButtonTexture
        searchButton.grid(row = 1, column = 5)

    def selectPCAP(self):
        try:
            global filePath
            filePath = filedialog.askopenfilename(title = 'Select PCAP file', filetypes = [('PCAP File', '*.pcap')])
        except:
            pass
    
    def analyzePCAP(self):
        try:
            if (filePath.split('/')[-1])[1:] == '.pcap':
                command = str('python packetAnalysis.py --pcap-file ' + filePath)
                try:
                    os.system(command)

                    global result
                    result = os.popen(command).read()
                    result = result.split('py-sn1tchRequireKeyword')
                    result = eval(result[-1])
                    
                    global indexedValues
                    indexedValues = {}

                    for packet in result.keys():
                        insert = self.packetTree.insert('', tk.END, text = str(packet[0]), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time']))))
                        indexedValues[insert] = packet
                    self.packetTree.bind('<Double-1>', self.onDoubleClick)

                except:
                    print('[!] Ensure all your folder names in the directory has no spaces.')

            else:
                print('[!] Ensure you have selected a PCAP file with the extension .pcap')
        except:
            pass
    
    def onDoubleClick(self, event):
        try:
            item = self.packetTree.selection()[0]
            win = tk.Toplevel()
            win.wm_title('Extra Details for packet: ' + str(self.packetTree.item(item, 'text')))
            win.configure(background = 'white')
            index = indexedValues[item]

            source = index[0]
            sport = index[1]
            destination = index[2]
            dport = index[3]
            startTime = result[index]['start_time']
            lastSeen = result[index]['last_seen']
            numOfPackets = result[index]['packets']
            bytes = result[index]['bytes']
            protocol = result[index]['protocol_name']
            anomalies = result[index]['flagged_anomalies']

            sourceLabel = tk.Label(win, text = 'Source: ' + str(source), background = 'white')
            sportLabel = tk.Label(win, text = 'Source Port: ' + str(sport), background = 'white')
            destinationLabel = tk.Label(win, text = 'Destination: ' + str(destination), background = 'white')
            dportLabel = tk.Label(win, text = 'Destination Port: ' + str(dport), background = 'white')
            startTimeLabel = tk.Label(win, text = 'Start Time: ' + str(startTime), background = 'white')
            lastSeenLabel = tk.Label(win, text = 'Last Seen: ' + str(lastSeen), background = 'white')
            numOfPacketsLabel = tk.Label(win, text = '# of Packets: ' + str(numOfPackets), background = 'white')
            bytesLabel = tk.Label(win, text = 'Bytes: ' + str(bytes), background = 'white')
            protocolLabel = tk.Label(win, text = 'Protocol: ' + str(protocol), background = 'white')
            anomaliesLabel = tk.Label(win, text = 'Anomalies Detected: ' + str(anomalies), background = 'white')

            sourceLabel.grid(row = 1, column = 1)
            sportLabel.grid(row = 2, column = 1)
            destinationLabel.grid(row = 3, column = 1)
            dportLabel.grid(row = 4, column = 1)
            startTimeLabel.grid(row = 5, column = 1)
            lastSeenLabel.grid(row = 6, column = 1)
            numOfPacketsLabel.grid(row = 7, column = 1)
            bytesLabel.grid(row = 8, column = 1)
            protocolLabel.grid(row = 9, column = 1)
            anomaliesLabel.grid(row = 10, column = 1)

            closeButton = tk.Button(win, text = 'Close', background = 'white', relief = 'raised', highlightthickness = 0, command = win.destroy)
            closeButton.grid(row = 11, column = 1)

        except:
            pass
    
    def searchTreeview(self, query):
        try:
            items = self.packetTree.get_children()
            for item in items:
                if query.lower() in str(self.packetTree.item(item)['values']).lower():
                    self.packetTree.selection_set(item)
                    self.packetTree.focus(item)
                    return
            messagebox.showinfo('Search', f'No results found for "{query}".')
        except:
            pass

class BenchmarkPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        BenchmarkPage.configure(self, background = 'white')

        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

        proofOfConceptLabel = tk.Label(self, text = 'This is to remain without function. This is just a proof of concept.', background = 'white')
        proofOfConceptLabel.grid(row = 5, column = 5)

class CapturePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        CapturePage.configure(self, background = 'white')

        textFont = tkinter.font.Font(family = 'Adawaita Sans', size = 12, weight = 'normal')
        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')
        startCaptureTexture = PhotoImage(file = 'Textures/startCapture.png')
        stopCaptureTexture = PhotoImage(file = 'Textures/stopCapture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

        self.directoryLabel = tk.Label(self, text = 'Save Directory: None', font = textFont, background = 'white')
        self.directoryLabel.grid(row = 1, column = 2)

        selectDirButton = tk.Button(self, text = 'Select Directory',
                                     font = textFont, 
                                     background = 'white', 
                                     relief = 'raised',
                                     command = self.selectDirectory)
        selectDirButton.grid(row = 2, column = 2)

        startCaptureButton = tk.Button(self, image = startCaptureTexture,
                                     width = 100, height = 100,
                                     background = 'white',
                                     relief = 'flat',
                                     highlightthickness = 0)
        startCaptureButton.image = startCaptureTexture
        startCaptureButton.grid(row = 3, column = 3)

        stopCaptureButton = tk.Button(self, image = stopCaptureTexture,
                                     width = 100, height = 100,
                                     background = 'white',
                                     relief = 'flat',
                                     highlightthickness = 0)
        stopCaptureButton.image = stopCaptureTexture
        stopCaptureButton.grid(row = 3, column = 4)

        proofOfConceptLabel = tk.Label(self, text = 'This is to remain without function. Please use the dataAggregation.py file to capture packets.', background = 'white')
        proofOfConceptLabel.grid(row = 5, column = 5)

    def selectDirectory(self):
        global directory
        directory = filedialog.askdirectory()
        
        splitDirectory = directory.split('/')
        splitDirectory = splitDirectory[-2:]
        rebuild = '/' + str(splitDirectory[0]) + '/' + str(splitDirectory[1])

        self.directoryLabel.config(text = 'Save Directory:' + rebuild)


class SettingsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        SettingsPage.configure(self, background = 'white')

        homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png')

        homeButton = tk.Button(self, image = homeButtonTexture, 
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu))
        homeButton.image = homeButtonTexture
        homeButton.grid(row = 1, column = 1)

        noticeLabel = tk.Label(self, background = 'white', text = 'It is ILLEGAL to collect and analyze packets on a network without the owners consent.')
        noticeLabel.grid(row = 2, column = 2)

if __name__ == '__main__':
    if moduleError == True:
        print('[!] Exiting program...')
        try:
            sys.exit()
        except:
            exit()
    DSR = DetermineSystemRequirements()

    'Start Front End'
    main = PageManager()
    main.mainloop()
