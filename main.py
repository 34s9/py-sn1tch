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


'DETERMINE SYSTEM REQUIREMENTS DOCUMENTATION'

class DetermineSystemRequirements: # Defining a class to encapsulate all the system checks. By using a class I can group related behavioural functions making it easy to initiate/run checks while keeping globals minimal.

    def __init__(self): # Running all the functions on initializaiton. Executing the cecks determining the readiness in results outputted to the console.
        print(self.determineOperatingEnv()) # Calling the OS/Version Environment and printing the result. I used a print statement to provide feedback before the GUI appears
        print(self.determineHardware()) # Calling the CPU/RAM check.
        print(self.determineStorage()) # Calls disk sizing check. The three functions cover the primary resources relevant to run the program

    def determineOperatingEnv(self): # Determining operating environment. (Current Operating System and Current Solution Version) Declaring a method to describe the runtime OS and product version. Seperation keeps each check reusable.
        currentVersion = os.path.basename(os.path.dirname(os.path.realpath(__file__))) # Computes the solution version from the directory name. This avoids maintaining a seperate version file and stays correct in packaged deployment off github.
        operatingSystem = os.name # Retrieves the name of the Operating system. Os.name is a stable and sufficient method for tailoring a user message without parsing detailed platform settings.
        
        if operatingSystem == 'nt': # Detected Windows Operating System. Generating a friendly status message. Branching makes the message specific.
            return 'Detected Windows operating system, running ' + currentVersion + ' of SIEM solution.' # Returns a composed string rather than printing, allowing the caller to control output.
        elif operatingSystem == 'posix': # Detected Linux Operating System. The phrasing informs the user which assumptions the program makes about the environment.
            return 'Detected Linux operating system, running ' + currentVersion + ' of SIEM solution.' # Maintaining a consistent structure across messages helps log parsing.
        else: # Fallback for unsual runtimes. Defensive coding ensures we still communicate state even if detection is ambigious.
            return '[!] Cannot detect operating system, running ' + currentVersion + ' of SIEM solution. Errors may occur.' # Includes a caution to set proper expectation and encourage further checks.
    
    def determineHardware(self): # Determing hardware requirements. (Amount of CPUS, ) 
        cpuCount = os.cpu_count() # Fetches logical CPU count. Using a fast built in method from OS.
        totalMemory = round(psutil.virtual_memory().total / 1073741824) # Uses psutil to read total ram bytes and conver to GiB. Rounding yields clean user-friendly numbers without misleading precision.
        
        if cpuCount is None or totalMemory == 0: # Guards against unknown metrics. Which can happen in rare environments. The message warns operators that performance predictions are unreliable.
            return '[!] Cannot determine CPU count or total Ram. Errors may occur.' # Communicating a message rather than a guess on the amount of cores.
        elif cpuCount < 4 or totalMemory < 4: # Enforcing a mininum for a responsive GUI and analysis. Thresholds are defaults for the program to run.
            return '[!] Detected less than 4 CPU cores or RAM installed. Errors may occur.' # Prefixed with warning marker to stand out in logs.
        else: # Success path reporting the detected resources clearly.
            return 'Detected ' + str(cpuCount) + ' CPU cores and ' + str(totalMemory) + ' GB of RAM.' # Returning metrics to help ensure the program runs in the correct environment.
    
    def determineStorage(self): # Seperate method to evaluate disk capacity.
        disk = round(psutil.disk_usage('/').total / (1024.0 ** 3)) # Quering the root file systems total size and coverts to GiB. Psutil is used over OS which is safer than shelling.
        if disk < 256: # Applies a baseline for large PCAP files and temporary artifacts. Storage pressure frequence causes failures os early detection matters.
            return '[!] Detected hard disk size of ' + str(disk) + ' GB, lower than minimum specs. Errors may occur.' # Explains the operation may still proceed but instability is possible.
        else: # reports acceptable capacity to reassure the operator
            return 'Detected ' + str(disk) + ' GB in hard disk.' # The explicit number aids capacity planning

## FRONT END ##
'Page Management'

class PageManager(tk.Tk): # Defining the main application window controller by subclassing Tk. Inheriting the logic needed for widgets to work.
    def __init__(self, screenName = None, baseName = None, className = "Tk", useTk = True, sync = False, use = None): # Mirrors Tks signature for compatibility.
        super().__init__(screenName, baseName, className, useTk, sync, use) # Ensures Tk is properly initialized via cooperative multiple inheritance patterns

        self.title('py-sn1tch') # Sets the window title for GUI, aiding the user experience

        container = tk.Frame(self, height = 400, width = 600) # Creating a frame to stack pages, using a single contained simplifies raising one page over the other without resetting geometry.
        container.pack(side = 'top', fill = 'both', expand = True) # Packing the container to occupy the window. Also using expand = True letting the contianer grow with window resizing for better UX

        self.pages = {} # Initializing a dictionary to hold page instances keyed by their class. A dictionary offers retrievaland avoids fragile string keys

        for p in (MainMenu, LogsPage, AlertsPage, BenchmarkPage, CapturePage, SettingsPage): # Iterating over the set of page classes to institiate them uniformly. A tuple is used for its lightwight and communicated the fixed page 'roster'
            page = p(container, self) # Initiates each page with the contianer as the parent and self as the controller Passing the controller enables pages to request navigation.

            self.pages[p] = page # registering the instance in the pages dicitonary. Using the class as key avoids name collisions and make calls concise.
            page.grid(row = 0, column = 0, sticky = 'nsew') # Laying each page in the same grid cell so tkraise can swap visibility. sticky=nsew ensures full frame expansion
        
        self.raisePage(MainMenu) # Displaying the main menu first. This provides a clear landing view for users entering the app.
    
    def raisePage(self, cont): # Defines a reusable method to bring any page to the front. Centralizing this avoids duplicating 'tkraise' calls accross pages.
        page = self.pages[cont] # Looks up the target page instance by class. Dictionary lookup is optimal for frequent navigation 
        page.tkraise() # Raises teh selected page above the selected page above others without destroying them. This preserves state between navigations, which is useful for tables and form inputs.


'Main Menu'

class MainMenu(tk.Frame): # declaring a page as a tk frame subclass. Using seperate classes per page encapsulates layout and logic, improving the maintainability of the solution
    def __init__(self, parent, controller): # Recieving the contianer and navigator so it can place widgets and change pages.
        tk.Frame.__init__(self, parent) # Initializing the base frame. Explicit base class __init__ is conventionla in Tkinter code keeping the intent of the class clear.

        menuFont = tkinter.font.Font(family = 'Adawaita Sans', size = 16, weight = 'bold') # Creating a bold display font for headings. A font object enables reuse across widgets and consistent branding.
        textFont = tkinter.font.Font(family = 'Adawaita Sans', size = 12, weight = 'normal') # Creates a normal text font for labels/buttons. Seperating ensures 'typographic hierachy' and readability

        MainMenu.configure(self, background = 'white') # Sets a neutral background. Consistent theming eases visual scanning and aligns with white icon backgrounds.
        try:
            logsButtonTexture = PhotoImage(file = 'Textures/logsButtonTexture.png') # Loads the logs button icon. Photoimage is the Tk native type. Avoiding bridges and ensuring compatibility.
            alertsButtonTexture = PhotoImage(file = 'Textures/alertsButtonTexture.png') # Loads the alerts icon. Seperate assets improve affordance.
            benchmarkButtonTexture = PhotoImage(file = 'Textures/benchmarkButtonTexture.png') # Loads the benchmark icon.
            captureButtonTexture = PhotoImage(file = 'Textures/captureButtonTexture.png') # Loads the capture icon. Images make large targets for quick navigation
            settingsButtonTexture = PhotoImage(file = 'Textures/settingsButtonTexture.png') # Loads the settings icon for the settings page.
            networkOfflineTexture = PhotoImage(file = 'Textures/networkOffline.png') # Loads the offiline indicatior icon.
            networkOnlineTexture = PhotoImage(file = 'Textures/networkOnline.png') # Loads the online indicator icon
        except:
            print('[!] Could not locate textures.')
            try:
                sys.exit()
            except:
                exit()
                
        self.networkOfflineLabel = tk.Label(self, image = networkOfflineTexture, width = 48, height = 48, background = 'white') # Creates an image label for the offline state and stores it on 'self' to prevent useless collection. 
        self.networkOfflineLabel.image = networkOfflineTexture # Keeping a python level reference to the image to satisfy tks requirements. Without this TK may drop the image leadig to a blank widget
        self.networkOfflineLabel.grid(row = 1, column = 1) # Placing the offline label on the grid initallity. Ensuring a visible default befor ethe frist network check completes

        self.networkOnlineLabel = tk.Label(self, image = networkOnlineTexture, width = 48, height = 48, background = 'white') # Preparing a parallel label for the online state, haing two lables makes show/hide via grid_forget straightforward and avoids stateful image swaps
        self.networkOnlineLabel.image = networkOnlineTexture # Retaining the image reference to ocmply with TKinter
        self.networkOnlineLabel.grid(row = 1, column = 1) # PLaces it in the same cell only one will be visible at a time depenidng on state.

        self.networkTextLabel = tk.Label(self, background = 'white', text = 'Network Disabled', font = textFont) # Creates the text indicator with a false default. Initalizing with a safe default avoids briefly shwoing an incorrect 'online' state
        self.networkTextLabel.grid(row = 1, column = 2) # Places the text beside the icon for immediate association

        refreshButton = tk.Button(self, text = 'Refresh Network', # Builds a manual refresh control so operator can recheck connectivity on demand. Also creating button
                                  font = textFont, 
                                  highlightthickness = 0,
                                  background = 'white',
                                  relief = 'raised',
                                  command = self.refreshNetwork) # Binding the button to the refresh handler Passing the bihd method is the most direct and readable approach.
        refreshButton.grid(row = 1, column = 7, padx = 10) # Places it ot the right of the icons creating a left ot right readability status

        logsButton = tk.Button(self, image = logsButtonTexture, # CReating a large icon button to open the logs page. Large hit targets are faster to acquire with a amouse and accessible on touch
                               highlightthickness = 0, 
                               background = 'white', 
                               width = 200, height = 200, 
                               relief = 'flat', 
                               command=lambda: controller.raisePage(LogsPage)) # Uses a lambda to defer the call until click time. Passing the class makes the call site short. For when the page changes
        
        logsButton.image = logsButtonTexture # Stores a reference to prevent tk for discarding the image
        logsButton.grid(row = 2, column = 2, padx = 10, pady = 10) # Positioning the button with adding to avoid cramping and to visaully group with its label.

        logsLabel = tk.Label(self, text = 'Logs', font = menuFont, background = 'white') # Adds a caption for the accesiblilty and clarity.
        logsLabel.grid(row = 3, column = 2, padx = 10) # Places the caption directly under the button to create a visual pairing.

        alertsButton = tk.Button(self, image = alertsButtonTexture, # Mirrors the logs button behavior for the Alerts page. Symmetry across buttons reduces 'cognitive load'.
                                 highlightthickness = 0, 
                                 background = 'white', 
                                 width = 200, height = 200, 
                                 relief = 'flat', 
                                 command=lambda: controller.raisePage(AlertsPage)) # On activation, the controller shows the Alerts page.
        
        alertsButton.image = alertsButtonTexture # Maintains a reference for Tk.
        alertsButton.grid(row = 2, column = 3, padx = 10, pady = 10) # Aligns this button in the next column to form a grid of actions.

        alertsLabel = tk.Label(self, text = 'Alerts', font = menuFont, background = 'white') # Provides the Alerts caption. Consistent labeling aids scanning.
        alertsLabel.grid(row = 3, column = 3, padx = 10) # Places it under the corresponding button for visual grouping.

        benchmarkButton = tk.Button(self, image = benchmarkButtonTexture,  # Adds a navigation button to a placeholder Benchmark page.
                                    highlightthickness = 0, 
                                    background = 'white', 
                                    width = 200, height = 200, 
                                    relief = 'flat', 
                                    command=lambda: controller.raisePage(BenchmarkPage)) # Keeps consistent navigation mechanics across pages.
        
        benchmarkButton.image = benchmarkButtonTexture # Retains the image reference.
        benchmarkButton.grid(row = 2, column = 4, padx = 10, pady = 10) # Aligns with the grid for symmetry.

        benchmarkLabel = tk.Label(self, text = 'Benchmark Device', font = menuFont, background = 'white') # Caption for the benchmark button. Descriptive labels help new users.
        benchmarkLabel.grid(row = 3, column = 4, padx = 10) # Places the label beneath the button to maintain consistency.

        captureButton = tk.Button(self, image = captureButtonTexture, # Adds a button for the Capture page. Even though capture is a proof‑of‑concept here, the navigation remains consistent.
                                   highlightthickness = 0, 
                                   background = 'white', 
                                   width = 200, height = 200, 
                                   relief = 'flat', 
                                   command=lambda: controller.raisePage(CapturePage)) # Clicking routes to the capture stub where directory selection is shown.
        
        captureButton.image = captureButtonTexture # Preserves the image.
        captureButton.grid(row = 2, column = 5, padx = 10, pady = 10) # Keeps grid layout uniform.

        captureLabel = tk.Label(self, text = 'Capture', font = menuFont, background = 'white') # Caption for capture. Naming aligns with the action icon.
        captureLabel.grid(row = 3, column = 5, padx = 10) # Places label beneath the button.

        settingsButton = tk.Button(self, image = settingsButtonTexture, # Adds a settings navigation control for legal notices and future configuration.
                                   highlightthickness = 0, 
                                   background = 'white', 
                                   width = 200, height = 200, 
                                   relief = 'flat', 
                                   command=lambda: controller.raisePage(SettingsPage)) # Routes to Settings on click.
        
        settingsButton.image = settingsButtonTexture # Retains image.
        settingsButton.grid(row = 2, column = 6, padx = 10, pady = 10) # Extends the grid to the next column.

        settingsLabel = tk.Label(self, text = 'Settings', font = menuFont, background = 'white') # Adds a label for settings to improve clarity.
        settingsLabel.grid(row = 3, column = 6, padx = 10) # Positions label below its icon button.

        self.refreshNetwork() # Immediately checks and updates the connectivity indicators. Running this at the end of init ensures the UI reflects real status as soon as it appears.

    def checkConnection(self): # Encapsulates the reachability test. Having a dedicated method enables reuse and easier unit testing by stubbing its return.
        global networkEnabled # Uses a module‑level variable so other components could consult the last known status.
        try: # Attempts a quick HTTPS GET to a well‑known IP.
            request.urlopen('https://8.8.8.8', timeout = 1) # Issues a network probe with a tight timeout. HTTPS to Google DNS is almost always reachable; the 1s timeout prevents UI stalls.
            networkEnabled = True # Records the status as True so other code can branch cheaply on connectivity. A boolean is ideal as connectivity is binary for this purpose.
            return True # Returns True to the caller so the UI update logic can proceed without inspecting globals.
        except request.URLError as err: # Catches URL‑related errors which indicate lack of reachability. Narrowing to URLError distinguishes it from unrelated exceptions.
            networkEnabled = False # Stores the offline state so other features can disable or warn accordingly.
            return False # Returns False to drive the offline UI branch.

    def refreshNetwork(self): # Consolidates all UI changes tied to connectivity into one method. This reduces duplication and ensures consistent behavior in all callers.
        try: # Wraps UI changes to avoid crashing the entire app on a minor drawing error.
            self.networkOfflineLabel.grid_forget()  # Hides the offline icon without destroying it. This makes toggling instantaneous and avoids re‑creating widgets.
            self.networkOnlineLabel.grid_forget() # Hides the online icon too so we can show exactly one after the check.

            if self.checkConnection() == True: # Explicit True comparison
                self.networkOnlineLabel.grid(row = 1, column = 1) # Shows the online icon in the fixed status location. This provides immediate visual confirmation.
                self.networkTextLabel.config(text = 'Network Enabled') # Updates the status text to match the icon. Redundant modalities aid accessibility.
            else: # Offline branch.
                self.networkOfflineLabel.grid(row = 1, column = 1) # Shows the offline icon instead, in the same grid cell.
                self.networkTextLabel.config(text = 'Network Disabled') # Sets text accordingly
        except: # Any UI exception here is non‑critical; we avoid interrupting the session and rely on the next refresh to recover.
            pass # No‑op is intentional; logging could be added if persistent issues are observed.


'Logs Page'

class LogsPage(tk.Frame): # Declares the log/packet view page. A separate class encapsulates its widgets and handlers, keeping the all the classes modular.
    def __init__(self, parent, controller): # Constructor wires up the UI and event bindings. Initalizing all the widgets.
        tk.Frame.__init__(self, parent) # Initializes the base frame for this page.

        LogsPage.configure(self, background = 'white') # Applies the application’s white theme to maintain consistency.
        try:
            homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png') # Loads the home icon for navigation. Icons speed up recognition compared to text.
            searchButtonTexture = PhotoImage(file = 'Textures/searchTexture.png') # Loads a search icon for the find action, keeping the UI compact.
        except:
            print('[!] Could not locate textures.')
            try:
                sys.exit()
            except:
                exit()
            
        homeButton = tk.Button(self, image = homeButtonTexture, # Creates a home navigation button with minimal chrome. Using an image keeps the UI consistent with the main menu.
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu)) # On click, navigates back to the main menu. Using a lambda defers execution until the event.
        homeButton.image = homeButtonTexture # Retains a reference to prevent Tk from GC‑ing the image. Without this, the image may disappear from the button.
        homeButton.grid(row = 1, column = 1) # Places the home button at the top left, a conventional location users expect for navigation.


        fileSelectButton = tk.Button(self, text = 'Select PCAP File',  # Adds a control to choose a PCAP to inspect. Explicit selection avoids hardcoded file paths and supports varied workflows.
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.selectPCAP) # Binds to the selection handler. Passing the bound method keeps concerns separated and testable.
        fileSelectButton.grid(row = 1, column = 2) # Places the button near the top controls for a logical flow.

##        readButton = tk.Button(self, text = 'Read File', # Adds the action to process the selected PCAP. Separating selection and processing gives users control and prevents accidental processing of large files.
##                                    background = 'white',
##                                    relief = 'raised',
##                                    highlightthickness = 0,
##                                    command = self.readPCAP) # Binds to the parser/loader. This keeps the function isolated from UI creation code.
##        readButton.grid(row = 1, column = 3) # Places the action next to selection for a left‑to‑right workflow.

        self.packetTree = ttk.Treeview(self, columns = ('Destination', 'Protocol', 'Information', 'Time')) # Creates a multi‑column table for packet/flow attributes. Treeview is chosen for its scalability and built‑in columns and headings.

        self.packetTree.heading('#0', text = 'Source') # Labels the implicit first column as Source, which Treeview calls #0. Using this for the source address keeps key data prominent.
        self.packetTree.heading('Destination', text = 'Destination') # Adds a Destination column header. Column headers enable clarity for the user.
        self.packetTree.heading('Protocol', text = 'Protocol') # Adds a Protocol column.
        self.packetTree.heading('Information', text = 'Information') # Adds an Information column to show anomaly flags or summaries.
        self.packetTree.heading('Time', text = 'Time') # Adds a Time column, here used to show a simple duration for quick triage.

        verticalScrollBar = ttk.Scrollbar(self, orient = tk.VERTICAL, command = self.packetTree.yview) # Creates a vertical scrollbar linked to the table. Large PCAPs require efficient navigation, and ttk provides native‑looking controls.
        self.packetTree.configure(yscrollcommand = verticalScrollBar.set) # Wires the table to update the scrollbar thumb on scroll. This two‑way binding ensures smooth UX.

        self.packetTree.grid(row = 2, column = 2) # Places the table centrally to maximize space for data. 
        verticalScrollBar.grid(row = 2, column = 3, sticky = 'ns') # Places the scrollbar alongside, stretching north‑south. Sticky ensures it spans the table vertically.

        self.searchBar = ttk.Entry(self) # Adds a text entry for quick filtering. An Entry is lightweight and sufficient for simple search.
        self.searchBar.grid(row = 1, column = 4) # Places the search field near other top controls to support a natural workflow.

        searchButton = tk.Button(self, image = searchButtonTexture, # Adds a compact icon button to trigger search. Keeping the control small saves header space for the table.
                                 width = 25, height = 25,
                                 background = 'white',
                                 relief = 'flat',
                                 highlightthickness = 0,
                                 command = lambda: self.searchTreeview(self.searchBar.get())) # On click, passes the current query to the search handler. Using a lambda avoids conflicts with parsing arguments.
        searchButton.image = searchButtonTexture # Keeps the image reference to satisfy Tk requirements.
        searchButton.grid(row = 1, column = 5) # Places the search icon immediately after the entry field, forming a tight control cluster.

    def selectPCAP(self): # Handles user‑driven PCAP selection. Separating concerns keeps file dialogs isolated from parsing logic.
        try: # Guards against dialog errors or user cancellations.
            global filePath # Stores the chosen path in a global so other methods can access it without threading state through multiple callbacks.
            filePath = filedialog.askopenfilename(title = 'Select PCAP file', filetypes = [('PCAP File', '*.pcap')]) # Opens an OS‑native file picker, filtering to .pcap files to reduce user error. The returned string path is easy to pass into shell commands.
            self.readPCAP()
        except: # Any exception here should not crash the UI; the user can simply retry.
            pass # Swallowing is acceptable because failure to select a file just leaves `filePath` unset.
    
    def readPCAP(self): # Invokes the analyzer on the selected PCAP and populates the table. This function also parses returned data into the UI structure.
        try: # Wraps the entire routine to ensure UI robustness under unexpected analyzer behavior or path issues.
            if (filePath.split('/')[-1])[1:] == '.pcap': # Performs a quick extension check by slicing the basename. While simplistic, it avoids additional filesystem calls and catches common mis‑selections.
                command = str('python packetAnalysis.py --pcap-file ' + filePath) # Constructs the analyzer command line. Using a string is the simplest way to store a command for future reference.
                try: # Runs the command and ingests results, tolerating common environment pitfalls such as path spacing.
                    os.system(command) # Executes the analyzer once without capturing output to allow any side effects (e.g., cache files). This mirrors the original behavior even if redundant.

                    global result # Declares a global to retain analyzer output for later detail views. A global allows the double‑click handler to access decoded data without pushing a parameter
                    result = os.popen(command).read() # Executes again and captures stdout. `os.popen` is a simple way to read a command’s output synchronously.
                    result = result.split('py-sn1tchRequireKeyword') # Splits on a known keyword to isolate the structured data payload. This is robust to extra prints from the analyzer.
                    result = eval(result[-1]) # Deserializes the last segment into a Python object. `eval` is fast and flexible
                    
                    global indexedValues # Prepares a mapping from table rows to packet keys for quick reverse lookups. A dict is ideal for information retrieval on double‑click.
                    indexedValues = {} # Initializes the mapping as empty, ready to be populated per inserted row.

                    for packet in result.keys(): # Iterates over each packet/flow key returned by the analyzer. Iteration order mirrors the analyzer’s key ordering (using Ordered Dictionariers)
                        if not result[packet]['flagged_anomalies']:
                            insert = self.packetTree.insert('', tk.END, text = str(packet[0]), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time'])))) # Inserts a row with Source in the tree column and other fields as values. Showing duration (last_seen - start_time) aids quick viewing.
                            indexedValues[insert] = packet # Stores the mapping from UI item ID to the analyzer key. This avoids recomputation or fragile parsing of label text.
                        else:
                            insert = self.packetTree.insert('', tk.END, text = str(packet[0]), tags =('alert'), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time'])))) # Inserts a row with Source in the tree column and other fields as values. Showing duration (last_seen - start_time) aids quick viewing.
                            indexedValues[insert] = packet # Stores the mapping from UI item ID to the analyzer key. This avoids recomputation or fragile parsing of label text.
      
                    self.packetTree.bind('<Double-1>', self.onDoubleClick) # Binds double‑click to a detail popup. This is a standard affordance for “open details” in tables.
                    self.packetTree.tag_configure('alert', background = 'gold')

                except: # Catches typical execution problems such as bad paths on Windows.
                    print('[!] Ensure all your folder names in the directory has no spaces.') # Emits an actionable tip since spaces commonly break naive command parsing.

            else: # If the file extension isn’t .pcap, guide the user rather than attempting to parse.
                print('[!] Ensure you have selected a PCAP file with the extension .pcap') # Clear guidance reduces support load and user frustration.
        except:  # Final safety net to ensure the UI remains responsive even if unexpected exceptions occur.
            pass # Non‑fatal; the user can retry after correcting input or environment.
    
    def onDoubleClick(self, event): # Opens a detailed view for the selected row. This promotes deeper analysis without leaving the context of the table.
        try:  # Guard against selection races or missing data.
            item = self.packetTree.selection()[0] # Retrieves the currently focused row’s ID. The first element works in a single‑selection tree.
            win = tk.Toplevel() # Creates a new top‑level window. Toplevel preserves the main table for reference while the user inspects details.
            win.wm_title('Extra Details for packet: ' + str(self.packetTree.item(item, 'text'))) # Titles the window with the Source field for quick identification. Including the key field helps when multiple dialogs are open.
            win.configure(background = 'white') # Applies the standard theme for visual consistency.
            index = indexedValues[item] # Looks up the analyzer key corresponding to this UI row. Dict lookup is consistent and reliable.

            source = index[0] # Extracts the source address from the key tuple. Tuples are compact and fast; positional access is cheap and clear here.
            sport = index[1] # Extracts the source port
            destination = index[2] # Extracts the destination address.
            dport = index[3] # Extracts the destination port.
            startTime = result[index]['start_time'] # Pulls the captured start time from the analyzer result dict.
            lastSeen = result[index]['last_seen'] # Pulls the last seen timestamp. This enables computation of duration and detection of long‑lived connections.
            numOfPackets = result[index]['packets'] # Reads packet count. This metric helps differentiate chatty vs sparse flows.
            bytes = result[index]['bytes'] # Reads byte count. Byte volume informs bandwidth usage and potential exfiltration.
            protocol = result[index]['protocol_name']  # Reads protocol name.
            anomalies = result[index]['flagged_anomalies'] # Reads anomaly flags synthesized by the analyzer. This is core to SIEM alerting workflows.

            sourceLabel = tk.Label(win, text = 'Source: ' + str(source), background = 'white') # Renders each attribute as a separate label for clarity. Individual labels are simple and require no custom layout logic.
            sportLabel = tk.Label(win, text = 'Source Port: ' + str(sport), background = 'white') # Presenting one fact per line improves readability and scanning speed.
            destinationLabel = tk.Label(win, text = 'Destination: ' + str(destination), background = 'white') # Aligning labels vertically creates a tidy details view.
            dportLabel = tk.Label(win, text = 'Destination Port: ' + str(dport), background = 'white') # Numeric fields are stringified for display without formatting surprises.
            startTimeLabel = tk.Label(win, text = 'Start Time: ' + str(startTime), background = 'white') # Times are displayed as raw values as produced.
            lastSeenLabel = tk.Label(win, text = 'Last Seen: ' + str(lastSeen), background = 'white') # Mirroring analyzer outputs maintains consistency for audits.
            numOfPacketsLabel = tk.Label(win, text = '# of Packets: ' + str(numOfPackets), background = 'white') # The hash symbol is a common shorthand for counts.
            bytesLabel = tk.Label(win, text = 'Bytes: ' + str(bytes), background = 'white')
            protocolLabel = tk.Label(win, text = 'Protocol: ' + str(protocol), background = 'white')
            anomaliesLabel = tk.Label(win, text = 'Anomalies Detected: ' + str(anomalies), background = 'white')

            sourceLabel.grid(row = 1, column = 1) # Places each label on its own row to create a readable stack. Grid provides straightforward row/column addressing.
            sportLabel.grid(row = 2, column = 1) # Sequential row numbers keep the layout logic simple and easily maintainable.
            destinationLabel.grid(row = 3, column = 1) # Consistent single‑column layout avoids horizontal scrolling in small windows.
            dportLabel.grid(row = 4, column = 1) # Ports grouped under their respective endpoints
            startTimeLabel.grid(row = 5, column = 1) # Chronological fields are placed one after another for narrative flow.
            lastSeenLabel.grid(row = 6, column = 1) 
            numOfPacketsLabel.grid(row = 7, column = 1)
            bytesLabel.grid(row = 8, column = 1)
            protocolLabel.grid(row = 9, column = 1)
            anomaliesLabel.grid(row = 10, column = 1)

            closeButton = tk.Button(win, text = 'Close', background = 'white', relief = 'raised', highlightthickness = 0, command = win.destroy) # Provides an explicit close control
            closeButton.grid(row = 11, column = 1) # Places the button after all labels to follow the natural top‑to‑bottom reading sequence.

        except: # Prevents a broken selection from taking down the UI. Any issues here are recoverable by simply closing the dialog or reselecting.
            pass # Intentional no operation.
    
    def searchTreeview(self, query): # Implements a simple search system across row value strings. Keeping it inline with avoiding external search dependencies.
        try: # Avoids widget state issues.
            items = self.packetTree.get_children() # Retrieves all row item IDs. Working with IDs is robust even if displayed values change.
            for item in items: # Iterates each row to check for a match. Linear search is adequate for modest table sizes typical in interactive viewing.
                if query.lower() in str(self.packetTree.item(item)['values']).lower(): # Performs a case‑insensitive substring match against the concatenated values. This provides forgiving search functions
                    self.packetTree.selection_set(item) # Highlights the first match to guide the user’s eye to the relevant row.
                    self.packetTree.focus(item) # Moves keyboard focus to the row to enable immediate key interactions.
                    return # Exits after the first match for speed and predictability
            messagebox.showinfo('Search', f'No results found for "{query}".') # Provides gentle feedback when nothing matches, avoiding silent failure.
        except: # Shields the UI from unexpected table state changes.
            pass # Fail‑safe behavior is to do nothing rather than crash.

'Alerts Page'

class AlertsPage(tk.Frame): # Declares the alerts page which shares the same structure with LogsPage. Keeping a separate class clarifies intent and allows future divergence in behavior.
    def __init__(self, parent, controller): # Constructor for alerts page.
        tk.Frame.__init__(self, parent) # Initializes the base frame.

        AlertsPage.configure(self, background = 'white') # Applies the shared white theme.
        try:
            homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png') # Loads navigation icon.
            searchButtonTexture = PhotoImage(file = 'Textures/searchTexture.png') # Loads search icon for the alerts table.
        except:
            print('[!] Could not locate textures.')
            try:
                sys.exit()
            except:
                exit()
                
        homeButton = tk.Button(self, image = homeButtonTexture, # Home button provides a fast escape back to the main menu.
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu)) # Uses controller to raise the main menu.
        homeButton.image = homeButtonTexture # Retains image reference as required by Tk.
        homeButton.grid(row = 1, column = 1) # Places the button in the conventional corner.

        fileSelectButton = tk.Button(self, text = 'Select PCAP File', # Allows the user to target a PCAP for alert analysis.
                                    background = 'white',
                                    relief = 'raised',
                                    highlightthickness = 0,
                                    command = self.selectPCAP) # Binds to file selection.
        fileSelectButton.grid(row = 1, column = 2) # Arranges controls left‑to‑right.

##        analyzeButton = tk.Button(self, text = 'Analyze File', # Action button to run the analyzer in the alerts context. Using a separate label clarifies intent vs “Read File”.
##                                    background = 'white',
##                                    relief = 'raised',
##                                    highlightthickness = 0,
##                                    command = self.analyzePCAP) # Binds the analysis action to a dedicated method.
##        analyzeButton.grid(row = 1, column = 3) # Places it next to selection for a clear workflow.

        self.packetTree = ttk.Treeview(self, columns = ('Destination', 'Protocol', 'Information', 'Time')) # Initializes the alerts table. Reusing column structure ensures consistency between pages.

        self.packetTree.heading('#0', text = 'Source') # Sets header for the tree column as Source.
        self.packetTree.heading('Destination', text = 'Destination') # Sets Destination header.
        self.packetTree.heading('Protocol', text = 'Protocol') # Sets Protocol header.
        self.packetTree.heading('Information', text = 'Information') # Sets Information header.
        self.packetTree.heading('Time', text = 'Time') # Sets Time header.

        verticalScrollBar = ttk.Scrollbar(self, orient = tk.VERTICAL, command = self.packetTree.yview) # Adds a scrollbar for large alert sets.
        self.packetTree.configure(yscrollcommand = verticalScrollBar.set) # Links table and scrollbar for synchronized scrolling.

        self.packetTree.grid(row = 2, column = 2, ) # Places the table on the grid. Central placement keeps focus on alert data.
        verticalScrollBar.grid(row = 2, column = 3, sticky = 'ns') # Places the scrollbar adjacent to the table.

        self.searchBar = ttk.Entry(self) # Adds a quick search field to filter alerts.
        self.searchBar.grid(row = 1, column = 4) # Positions the search field near action buttons.

        searchButton = tk.Button(self, image = searchButtonTexture, # Adds a compact search trigger button.
                                 width = 25, height = 25,
                                 background = 'white',
                                 relief = 'flat',
                                 highlightthickness = 0,
                                 command = lambda: self.searchTreeview(self.searchBar.get())) # Executes the search when clicked, passing current query.
        searchButton.image = searchButtonTexture # Retains image reference.
        searchButton.grid(row = 1, column = 5) # Places it immediately after the entry field for intuitive grouping.

    def selectPCAP(self): # File selection mirrors LogsPage for consistent user experience.
        try: # Protects against dialog issues or cancellations.
            global filePath # Uses a global path for simplicity in this small app. This allows the analyze method to access the same selection without additional wiring.
            filePath = filedialog.askopenfilename(title = 'Select PCAP file', filetypes = [('PCAP File', '*.pcap')]) # Uses a file filter to reduce mis‑clicks and ensure analyzer compatibility.
            self.analyzePCAP()
        except: # Fail‑safe in case of OS dialog errors.
            pass # The user can retry selection without restarting the app.
    
    def analyzePCAP(self): # Runs the analyzer and populates the alerts table. Functionally similar to readPCAP but keeps naming aligned with alert semantics.
        try: # Wraps for resilience against analyzer errors.
            if (filePath.split('/')[-1])[1:] == '.pcap': # Quick extension check to avoid invoking the analyzer on an incompatible file.
                command = str('python packetAnalysis.py --pcap-file ' + filePath) # Constructs the analyzer command.
                try: # Attempt to run and read results, tolerating common environment problems.
                    os.system(command) # Executes the analyzer for any side effects required before reading output. Mirrors original flow even if redundant.

                    global result # Declares global to share analyzer output with the double‑click handler.
                    result = os.popen(command).read() # Captures analyzer stdout as a string for parsing.
                    result = result.split('py-sn1tchRequireKeyword') # Splits by keyword to find the structured payload among other prints.
                    result = eval(result[-1]) # Converts the payload to Python data structures
                    
                    global indexedValuesAnalyzed # Mapping from row IDs to analyzer keys accelerates detail retrieval.
                    indexedValuesAnalyzed = {} # Resets mapping for the new analysis run.

                    for packet in result.keys(): # Iterates flows/packets returned by the analyzer.
                        if not result[packet]['flagged_anomalies']:
                            insert = self.packetTree.insert('', tk.END, text = str(packet[0]), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time'])))) # Inserts a row with Source in the tree column and other fields as values. Showing duration (last_seen - start_time) aids quick viewing.
                            indexedValues[insert] = packet # Stores the mapping from UI item ID to the analyzer key. This avoids recomputation or fragile parsing of label text.
                        else:
                            insert = self.packetTree.insert('', tk.END, text = str(packet[0]), tags =('alert'), values = (packet[2], result[packet]['protocol_name'], result[packet]['flagged_anomalies'], str(int(result[packet]['last_seen']) - int(result[packet]['start_time'])))) # Inserts a row with Source in the tree column and other fields as values. Showing duration (last_seen - start_time) aids quick viewing.
                            indexedValues[insert] = packet # Stores the mapping from UI item ID to the analyzer key. This avoids recomputation or fragile parsing of label text.
                    self.packetTree.bind('<Double-1>', self.onDoubleClick) # Enables double‑click to open details for any alert row.

                except: # Catches path/exec errors and provides a likely remediation.
                    print('[!] Ensure all your folder names in the directory has no spaces.') # Path spacing is a common cause of shell command misparsing.

            else: # The selected file is not a .pcap, so we inform the user and do nothing.
                print('[!] Ensure you have selected a PCAP file with the extension .pcap') # Direct, actionable guidance minimizes confusion when an error occurs.
        except: # Final guard to keep UI responsive on unexpected exceptions.
            pass # No further action; user can retry.
    
    def onDoubleClick(self, event): # Opens a detailed alert view for the selected row.
        try: # Catches cases where selection is empty or data missing.
            item = self.packetTree.selection()[0] # Fetches the selected item ID from the Treeview.
            win = tk.Toplevel() # Spawns a new top‑level window to display details without obscuring the table.
            win.wm_title('Extra Details for packet: ' + str(self.packetTree.item(item, 'text'))) # Titles include the Source field to anchor user context.
            win.configure(background = 'white') # Applies theme for a cohesive look.
            index = indexedValuesAnalyzed[item] # Retrieves the analyzer key for this row through the mapping

            source = index[0] # Unpacks source IP from the key tuple. Tuple access is fast and explicit here.
            sport = index[1] # Unpacks source port.
            destination = index[2] # Unpacks destination IP.
            dport = index[3] # Unpacks destination port.
            startTime = result[index]['start_time'] # Reads structured start time from analyzer results.
            lastSeen = result[index]['last_seen'] # Reads last seen time.
            numOfPackets = result[index]['packets'] # Reads packet count.
            bytes = result[index]['bytes'] # Reads total bytes.
            protocol = result[index]['protocol_name'] # Reads protocol label.
            anomalies = result[index]['flagged_anomalies'] # Reads anomaly summary.

            sourceLabel = tk.Label(win, text = 'Source: ' + str(source), background = 'white') # Renders each attribute as a separate label for clarity. Individual labels are simple and require no custom layout logic.
            sportLabel = tk.Label(win, text = 'Source Port: ' + str(sport), background = 'white') # Presenting one fact per line improves readability and scanning speed.
            destinationLabel = tk.Label(win, text = 'Destination: ' + str(destination), background = 'white') # Aligning labels vertically creates a tidy details view.
            dportLabel = tk.Label(win, text = 'Destination Port: ' + str(dport), background = 'white') # Numeric fields are stringified for display without formatting surprises.
            startTimeLabel = tk.Label(win, text = 'Start Time: ' + str(startTime), background = 'white') # Times are displayed as raw values as produced.
            lastSeenLabel = tk.Label(win, text = 'Last Seen: ' + str(lastSeen), background = 'white') # Mirroring analyzer outputs maintains consistency for audits.
            numOfPacketsLabel = tk.Label(win, text = '# of Packets: ' + str(numOfPackets), background = 'white') # The hash symbol is a common shorthand for counts.
            bytesLabel = tk.Label(win, text = 'Bytes: ' + str(bytes), background = 'white')
            protocolLabel = tk.Label(win, text = 'Protocol: ' + str(protocol), background = 'white')
            anomaliesLabel = tk.Label(win, text = 'Anomalies Detected: ' + str(anomalies), background = 'white')

            sourceLabel.grid(row = 1, column = 1) # Places each label on its own row to create a readable stack. Grid provides straightforward row/column addressing.
            sportLabel.grid(row = 2, column = 1) # Sequential row numbers keep the layout logic simple and easily maintainable.
            destinationLabel.grid(row = 3, column = 1) # Consistent single‑column layout avoids horizontal scrolling in small windows.
            dportLabel.grid(row = 4, column = 1) # Ports grouped under their respective endpoints
            startTimeLabel.grid(row = 5, column = 1) # Chronological fields are placed one after another for narrative flow.
            lastSeenLabel.grid(row = 6, column = 1) 
            numOfPacketsLabel.grid(row = 7, column = 1)
            bytesLabel.grid(row = 8, column = 1)
            protocolLabel.grid(row = 9, column = 1)
            anomaliesLabel.grid(row = 10, column = 1)

            closeButton = tk.Button(win, text = 'Close', background = 'white', relief = 'raised', highlightthickness = 0, command = win.destroy) # Gives an explicit exit affordance inside the dialog.
            closeButton.grid(row = 11, column = 1) # Places the button at the bottom to follow reading order.

        except: # Prevents UI failure if selection disappears or data is malformed.
            pass # The user can retry without restarting the app.
    
    def searchTreeview(self, query): # Implements a simple search across alert rows.
        try: # Guards against widget state changes during search.
            items = self.packetTree.get_children() # Fetches all row IDs for iteration.
            for item in items: # Scans each row linearly. Adequate for interactive tables.
                if query.lower() in str(self.packetTree.item(item)['values']).lower(): # Case‑insensitive containment check on concatenated values. Simple and effective for quick find.
                    self.packetTree.selection_set(item) # Selects the matching row so users can immediately open details.
                    self.packetTree.focus(item) # Shifts keyboard focus to the row to enable keyboard navigation.
                    return # Stops after the first match to keep behavior predictable.
            messagebox.showinfo('Search', f'No results found for "{query}".') # Feedback when nothing matches to avoid silent failure.
        except: # Ensures transient issues don’t crash the UI.
            pass # A no‑op is safer than raising in a user interaction path.

'Benchmarking Page'

class BenchmarkPage(tk.Frame): # Placeholder page indicating future functionality. Keeping this page maintains consistent navigation and sets expectations.
    def __init__(self, parent, controller): # Constructor builds minimal UI.
        tk.Frame.__init__(self, parent) # Initializes the base frame.

        BenchmarkPage.configure(self, background = 'white') # Applies theme to stay visually consistent.
        try:
            homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png') # Loads home icon for return navigation.
        except:
            print('[!] Could not locate textures.')
            try:
                sys.exit()
            except:
                exit()
                
        homeButton = tk.Button(self, image = homeButtonTexture, # Creates a home button as on other pages to maintain learned behavior.
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu)) # Navigates back to main menu on click.
        homeButton.image = homeButtonTexture # Retains image reference per Tk requirements.
        homeButton.grid(row = 1, column = 1) # Places the control in the standard location.

        proofOfConceptLabel = tk.Label(self, text = 'This is to remain without function. This is just a proof of concept.', background = 'white') # Informs users that the page is intentionally inert. This manages expectations and reduces confusion.
        proofOfConceptLabel.grid(row = 5, column = 5) # Places the label in the grid; exact position is not critical for a placeholder.

'Capture Page'

class CapturePage(tk.Frame): # Capture page demonstrates directory selection and capture controls without actually starting capture. This decouples UI from privileged operations handled elsewhere.
    def __init__(self, parent, controller): # Constructs the capture UI.
        tk.Frame.__init__(self, parent) # Initializes the base frame.
        
        CapturePage.configure(self, background = 'white') # Applies theme.
        textFont = tkinter.font.Font(family = 'Adawaita Sans', size = 12, weight = 'normal') # Sets a readable font for labels and buttons on this page. Consistent font objects ensure uniform rendering.
        
        try:    
            homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png') # Loads the home icon.
            startCaptureTexture = PhotoImage(file = 'Textures/startCapture.png') # Loads a start icon. Even though non‑functional, the affordance primes users for future behavior.
            stopCaptureTexture = PhotoImage(file = 'Textures/stopCapture.png') # Loads a stop icon to complete the control pair.
        except:
            print('[!] Could not locate textures.')
            try:
                sys.exit()
            except:
                exit()

        homeButton = tk.Button(self, image = homeButtonTexture, # Home button to return to main menu.
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu)) # Binds navigation back to the main menu.
        homeButton.image = homeButtonTexture # Keeps a reference to the image object for Tk.
        homeButton.grid(row = 1, column = 1) # Positions as in other pages for muscle memory.

        self.directoryLabel = tk.Label(self, text = 'Save Directory: None', font = textFont, background = 'white') # Displays the selected directory path for PCAP output. A label is sufficient as this is display‑only information.
        self.directoryLabel.grid(row = 1, column = 2) # Places near top to keep status visible.

        selectDirButton = tk.Button(self, text = 'Select Directory', # Provides a button to choose where to save captures. This separates side‑effectful path selection from accidental clicks.
                                     font = textFont, 
                                     background = 'white', 
                                     relief = 'raised',
                                     command = self.selectDirectory) # Binds to the directory selection dialog.
        selectDirButton.grid(row = 2, column = 2) # Places the label.

        startCaptureButton = tk.Button(self, image = startCaptureTexture, # Non‑functional start button present for UX preview. This allows early usability testing without privileged operations.
                                     width = 100, height = 100,
                                     background = 'white',
                                     relief = 'flat',
                                     highlightthickness = 0)
        startCaptureButton.image = startCaptureTexture # Keeps the image alive for Tk.
        startCaptureButton.grid(row = 3, column = 3) # Positions to the left of stop to indicate flow.

        stopCaptureButton = tk.Button(self, image = stopCaptureTexture, # Non‑functional stop button complements start. Having both clarifies intended future interactions.
                                     width = 100, height = 100,
                                     background = 'white',
                                     relief = 'flat',
                                     highlightthickness = 0)
        stopCaptureButton.image = stopCaptureTexture # Retains image reference.
        stopCaptureButton.grid(row = 3, column = 4) # Positions to the right of start, following conventional control order.

        proofOfConceptLabel = tk.Label(self, text = 'This is to remain without function. Please use the dataAggregation.py file to capture packets.', background = 'white') # Explicitly tells users where capture functionality actually lives, avoiding confusion and privilege issues in the GUI.
        proofOfConceptLabel.grid(row = 5, column = 5)  # Places the explanatory label prominently.

    def selectDirectory(self): # Handles directory selection and updates the UI to reflect the choice. Keeping it in a function isolates system dialogs from widget setup.
        global directory # Stores the chosen directory at module scope for potential access by future capture routines.
        directory = filedialog.askdirectory() # Opens a native directory chooser. Using OS dialogs minimizes user error and requires no custom UI.
        
        splitDirectory = directory.split('/') # Splits the path by `/` to build a compact display. String operations are sufficient; no need for os.path here since this is purely cosmetic.
        splitDirectory = splitDirectory[-2:] # Keeps only the last two path components to avoid overly long labels. This balances information density with readability.
        rebuild = '/' + str(splitDirectory[0]) + '/' + str(splitDirectory[1]) # Reassembles a succinct path preview. Explicit concatenation keeps behavior transparent.

        self.directoryLabel.config(text = 'Save Directory:' + rebuild) # Updates the label text to show the selected path. Immediate feedback confirms the action for the user.

'Settings Page'

class SettingsPage(tk.Frame): # Settings page holds legal/ethical guidance and would host configurable options in the future. A separate page communicates seriousness and centralizes such notices.
    def __init__(self, parent, controller): # Constructs the settings UI.
        tk.Frame.__init__(self, parent) # Initializes the base frame.

        SettingsPage.configure(self, background = 'white') # Applies shared theme.
        try:
            homeButtonTexture = PhotoImage(file = 'Textures/homeButtonTexture.png') # Loads home icon for consistent navigation.
        except:
            print('[!] Could not locate textures.') 
            try:
                sys.exit()
            except:
                exit()
                
        homeButton = tk.Button(self, image = homeButtonTexture, # Provides return to main menu.
                               width = 50, height = 50, 
                               background = 'white',
                               relief = 'flat',
                               highlightthickness = 0,
                               command = lambda: controller.raisePage(MainMenu)) # Binds to page raise for navigation.
        homeButton.image = homeButtonTexture # Maintains image reference to satisfy Tk.
        homeButton.grid(row = 1, column = 1) # Standard placement fosters predictability.

        noticeLabel = tk.Label(self, background = 'white', text = 'It is ILLEGAL to collect and analyze packets on a network without the owners consent.') # Displays a clear legal warning. Making this explicit helps ensure ethical use and reduces liability.
        noticeLabel.grid(row = 2, column = 2) # Places the notice centrally to maximize visibility.

'Runtime Script'

if __name__ == '__main__':  # Ensures this block runs only when the script is executed directly. This allows importing the module for testing without launching the GUI.
    if moduleError == True: # Checks the global dependency flag set during imports. Using a boolean gate here is the simplest and most readable way to block startup on fatal issues.
        print('[!] Exiting program...') # Communicates the reason for exiting to stdout so operators know to install missing modules or adjust privileges.
        try: # Attempts a clean interpreter exit.
            sys.exit() # Exits using sys for clarity and potential status codes in the future. Clean exit frees OS resources and avoids zombie processes.
        except:  # Fallback if sys.exit is intercepted or unavailable (extremely rare in standard CPython runs).
            exit()  # Uses the built‑in exit as a backup, ensuring termination regardless of environment quirks.
    DSR = DetermineSystemRequirements()  # Instantiates the system requirements checker. Running this now prints environment suitability before any GUI windows appear.

    'Start Front End'  # A benign string literal acts as a no‑op marker. While it has no effect, it documents the transition in a way that won’t break execution.
    main = PageManager()  # Creates the main GUI controller/window. Instantiation builds all pages and prepares navigation.
    main.mainloop()  # Enters Tk’s event loop, yielding control to the GUI. From here, callbacks drive application behavior until the window closes.
