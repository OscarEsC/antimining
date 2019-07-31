# Para trabajar con el registro en Windows
from _winreg import *
# Para trabajar con los procesos de Windows
import wmi
import psutil
# Para leer la configuracion de un archivo.
import ConfigParser

user_temp_rute    = "\%userprofile%\\AppData\\Local\\Temp\\cript.bat"
user_startup_rute = "\%userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\cript.bat"

def keysHKLM():
    '''
        Funcion que lee las llaves contenidas en 
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    '''   
    #print r"*** Leyendo la llave HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ***"
    aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
    aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") 
    dic_HKLM = {}
    for i in range(QueryInfoKey(aKey)[1]):                                         
        try:
            name,data,_type = EnumValue(aKey,i)
            dic_HKLM[i] = [name,data,_type]
            #print i, name, data, _type
        except EnvironmentError:                                               
            print "Tienes",i," tareas iniciadas al iniciar"
            break          
    CloseKey(aKey) 
    CloseKey(aReg)
    #print dic_HKLM.values()
    return dic_HKLM

def keysHKCU():
    '''
        Funcion que lee las llaves contenidas en 
        HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    '''     
    #print r"*** Leyendo la llave HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ***"
    aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
    aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") 
    dic_HKCU = {}
    for i in range(QueryInfoKey(aKey)[1]):                                         
        try:
            name,data,_type = EnumValue(aKey,i)
            dic_HKCU[i] = [name,data,_type]
            #print i, name, data, _type
        except EnvironmentError:                                               
            print "Tienes",i," tareas iniciadas al iniciar"
            break
    CloseKey(aKey)
    CloseKey(aReg)
    #print dic_HKCU.values()
    return dic_HKCU          

def find_key(dic_HKLM,dic_HKCU,temp_rute):
    '''
        Funcion que busca la direccion del folder donde el malware se aloja, dentro de un diccionario 
        que contine los registros de las llaves:
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
            HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        esta regresa una lista de cada HK si existe una concidencia.
    '''
    match_HKLM = []
    match_HKCU = []
    for key, value in dic_HKLM.items():
        if (temp_rute == str(value[1])):
            match_HKLM.append(key)
        else:
            continue
    for key, value in dic_HKCU.items():
        if (temp_rute == str(value[1])):
            match_HKCU.append(key)
        else:
            continue
    return match_HKLM,match_HKCU

def keyAlert(match_HKLM,match_HKCU):
    if not match_HKLM:
        print "Todo Normal en HKLM"
    else:
        # Se realizara el proceso para la ALERTA despues de detectar una llave igual a la del malware
        print "ALERTA: se encontro una llave en HKLM"
    if not match_HKCU:
        print "Todo Normal en HKCU"
    else:
        # Se realizara el proceso para la ALERTA despues de detectar una llave igual a la del malware
        print "ALERTA: se encontro una llave en HKCU"

def process(pid):
    '''
        Funcion que recibe un PID y muestra su Nombre y Ruta de ejecucion. 
    '''
    c = wmi.WMI()
    for process in c.Win32_Process ():
        if process.ProcessId == int(pid):
            print process.ProcessId, process.Name, process.ExecutablePath
    
    '''
    py = psutil.Process(9504)
    THRESHOLD = 100 * 1024 * 1024  # 100MB
    mem = psutil.virtual_memory()
    if mem.available <= THRESHOLD:
        print("warning")
    memoryUse = py.memory_info()[0]/2.**30  # memory use in GB...I think
    print('memory use:', memoryUse)

    # Iteracion sobre todos los procesos ejecutados
    for proc in psutil.process_iter():
        try:
            # Obtengo el nombre y pid de cada proceso.
            processName = proc.name()
            processID = proc.pid
            print(processName, processID)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    listOfProcessNames = list()
    # Itera todos los procesos de ejecucion
    for proc in psutil.process_iter():
    # Obtener detalles de procesos como diccionario
        pInfoDict = proc.as_dict(attrs=['pid', 'name', 'cpu_percent'])
    # Append al dictorio los detalles de los procesos in forma de lista
        listOfProcessNames.append(pInfoDict)
    for element in listOfProcessNames:
        print element
    '''
def getListOfProcess():
    '''
        Funcion que obtinen una lista de los procesos ejecutados.
    '''
    listOfProcObjects = []
    # Itera sobre la lista
    for proc in psutil.process_iter():
       try:
           # Trea los detalles de los procesos como un dictionario
           pinfo = proc.as_dict(attrs=['pid', 'name', 'cpu_percent'])
           pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
           # Append del dicionario a la lista
           listOfProcObjects.append(pinfo)
       except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
           pass
 
    # Ordena los procesos por algun detalle de los procesos.
    listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['cpu_percent'], reverse=True)
 
    return listOfProcObjects

def findPID(pid):
    '''
        Funcion que busca dentro de una lista de procesos un PID en particular y regresa el nombre del proceso.
    '''
    processInfo = []
    for elem in listOfRunningProcess:
        #print(elem)
        for key, value in elem.items():
            if key == 'pid':
                if value == int(pid):
                    for i in elem.values():
                        processInfo.append(i)
    return processInfo 

def loadCfg():
    '''
        Funcion que carga los parametros colocados en un archivo de configuracion como variables
    '''
    config = ConfigParser.ConfigParser()
    config.read("config.ini")
    domain      = config.get("myconfig", "domain")
    port        = config.get("myconfig", "port")
    malwarePath = config.get("myconfig", "malwarePath")
    malwareName = config.get("myconfig", "malwareName")
    malwarePid  = config.get("myconfig", "malwarePid")

    return domain,port,malwarePath,malwareName,malwarePid       

if __name__== "__main__":
    # Obtenemos los parametros desde un archivo de configuracion
    domain,port,malwarePath,malwareName,malwarePid = loadCfg()
    # Obtenemos los diccionarios relacionados a HKLM y HKCU, en cada uno tenemos las caracteristicas de las llaves.
    dic_HKLM = keysHKLM()
    dic_HKCU = keysHKCU()
    # Listas que contiene los indices donde se encontraron la cadena identificada donde se almacena el malware dentro de la llave de registro.
    match_HKLM,match_HKCU = find_key(dic_HKLM,dic_HKCU,malwarePath)
    # Proceso que se realizara cuando se identifica una concidencia en las llaves
    keyAlert(match_HKLM,match_HKCU)
    process(malwarePid)
    # Obtenemos una lista de los proceso ejecutados.
    listOfRunningProcess = getListOfProcess()
    #for i in listOfRunningProcess[:10]:
     #   print i
    # Buscamos un especifico PID y regresamos una lista con sus detalles.
    processInfo = findPID(malwarePid)
    # Imprimimos los detalles del proceso
    for i in processInfo:
        print i

