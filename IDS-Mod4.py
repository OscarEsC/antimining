# Para trabajar con el registro en Windows
from _winreg import *
# Para trabajar con los procesos de Windows
import wmi
import psutil
# Para leer la configuracion de un archivo.
import ConfigParser
# Para buscar contenido especifico dentro de las llaves de Registro.
import re
import os

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
def find_key(dic_HKLM,dic_HKCU):
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
        #cadena = "cript.exe -a sha256d -o stratum+tcp://nya.kano.is:3333 -u 14SJbPSPtXucTcthxTzmCmQXSKatGpV7fQ -p x -q -B"
        match = re.match(r"(^\w+?\.exe?.-a?.[axiom|blake|blakecoin|blake2s|bmw|c11/flax|cryptolight|cryptonight|decred|dmd\-gr|drop|fresh|groestl|heavy|keccak|luffa|lyra2re|lyra2rev2|myr\-gr|neoscrypt|nist5|pluck|pentablake|quark|qubit|scrypt|scrypt\:N|scrypt\-jane:N|shavite3|sha256d|sia|sib|skein|skein2|s3|timetravel|vanilla|x11evo|x11|x13|x14|x15|x17|xevan|yescrypt|zr5]+)", str(value[1]).rstrip("\n\r"))
        if match:
        #if (temp_rute == str(value[1]).rstrip("\n\r")):
            match_HKLM.append(key)
        else:
            continue
    for key, value in dic_HKCU.items():
        match = re.match(r"(^\w+?\.exe?.-a?.[axiom|blake|blakecoin|blake2s|bmw|c11/flax|cryptolight|cryptonight|decred|dmd\-gr|drop|fresh|groestl|heavy|keccak|luffa|lyra2re|lyra2rev2|myr\-gr|neoscrypt|nist5|pluck|pentablake|quark|qubit|scrypt|scrypt\:N|scrypt\-jane:N|shavite3|sha256d|sia|sib|skein|skein2|s3|timetravel|vanilla|x11evo|x11|x13|x14|x15|x17|xevan|yescrypt|zr5]+)", str(value[1]).rstrip("\n\r"))
        if match:
        #if (temp_rute == str(value[1]).rstrip("\n\r")):
            match_HKCU.append(key)
        else:
            continue
    return match_HKLM,match_HKCU
def find_key_with_exe(dic_HKLM,dic_HKCU,highProcesses):
    '''
        Funcion que busca la direccion del folder donde el malware se aloja, dentro de un diccionario 
        que contine los registros de las llaves:
            HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
            HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        esta regresa una lista de cada HK si existe una concidencia.
    '''
    match_HKLM = []
    match_HKCU = []
    for proc in highProcesses:
        exe = proc.values()[3]
        for key, value in dic_HKLM.items():
            if exe in str(value[1]).rstrip("\n\r"):
            #if (temp_rute == str(value[1]).rstrip("\n\r")):
                match_HKLM.append(key)
            else:
                continue
        #print match_HKLM
        for key, value in dic_HKCU.items():
            if exe in str(value[1]).rstrip("\n\r"):
            #if (temp_rute == str(value[1]).rstrip("\n\r")):
                match_HKCU.append(key)
            else:
                continue
        #print match_HKCU
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
def procAlert(processInfo):
    highProcesses = []
    for proc in processInfo:
        #print proc
        cpuAlert= False
        ramAlert = False
        # Si el proceso cosume un % mayor a 70% de CPU
        if proc.values()[4] >= 70.0:
            print "Alerta de aumento de CPU en el proceso: %s con PID %s consumo CPU: %.2f   " %(proc.values()[3],proc.values()[2],proc.values()[4])
            cpuAlert = True
        # Si el proceso cosume mas de 350MB de memoria RAM
        if proc.values()[0] >= 350.0:
            print "Alerta de aumento de CPU en el proceso: %s con PID %s consumo RAM: %.2f Mb" %(proc.values()[3],proc.values()[2],proc.values()[0])
            ramAlert = True
        if cpuAlert:
            highProcesses.append(proc)
    return highProcesses
def pidInfo(pids):
    '''
        Funcion que obtinen una lista de los detalles de un unico proceso en ejecucion.
    '''
    detailOfProcess = []
    for pid in pids:
        try:
            # Itera sobre la lista
            proc = psutil.Process(int(pid))
            # Trea los detalles de los procesos como un dictionario
            pinfo = proc.as_dict(attrs=['pid','name', 'exe'])
            pinfo['cpu_percent'] = proc.cpu_percent(interval=0.1)
            pinfo['vms'] = proc.memory_info().vms / (1024 * 1024) # RAM en MB
            # Append del dicionario a la lista
            detailOfProcess.append(pinfo)
            #print detailOfProcess
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return detailOfProcess    
def getListOfProcess():
    '''
        Funcion que obtinen una lista de los procesos ejecutados.
    '''
    listOfProcObjects = []
    # Itera sobre la lista
    for proc in psutil.process_iter():
       try:
           # Trea los detalles de los procesos como un dictionario
           pinfo = proc.as_dict(attrs=['pid', 'name', 'exe'])
           pinfo['cpu_percent'] = proc.cpu_percent(interval=0.1)
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
def findFiles(malwareWindowsPath):
    path = malwareWindowsPath
    filesBatInPath  = []
    malwareFilesBat = []
    exeFiles        = []
    #fileslist = [file for file in os.listdir(path) if file.endswith('.bat')]
    for file in os.listdir(path):
        if file.endswith('.bat'):
            filesBatInPath.append(os.path.join(path,file))
    #malwareFiles = [file for file in filesBatInPath if "cript.exe -a" in open(file).read()]
    for file in filesBatInPath:
        f = open(file,'r').read()
        match = re.match(r"((.*(\w+\.exe))?.-a?.)[axiom|blake|blakecoin|blake2s|bmw|c11/flax|cryptolight|cryptonight|decred|dmd\-gr|drop|fresh|groestl|heavy|keccak|luffa|lyra2re|lyra2rev2|myr\-gr|neoscrypt|nist5|pluck|pentablake|quark|qubit|scrypt|scrypt\:N|scrypt\-jane:N|shavite3|sha256d|sia|sib|skein|skein2|s3|timetravel|vanilla|x11evo|x11|x13|x14|x15|x17|xevan|yescrypt|zr5]+", f)
        if match:
            malwareFilesBat.append(file)
            exeFiles.append(match.group(2).split()[1])
    return malwareFilesBat,exeFiles
def loadCfg():
    '''
        Funcion que carga los parametros colocados en un archivo de configuracion como variables
    '''
    config = ConfigParser.ConfigParser()
    config.read("config.ini")
    domain             = config.get("myconfig", "domain")
    port               = config.get("myconfig", "port")
    malwareWindowsPath = config.get("myconfig", "malwareWindowsPath")
    malwarePath        = config.get("myconfig", "malwarePath")
    malwareName        = config.get("myconfig", "malwareName")
    #malwarePid         = config.get("myconfig", "malwarePid")

    return domain,port,malwareWindowsPath,malwarePath,malwareName#,malwarePid       
if __name__== "__main__":
    # Obtenemos los parametros desde un archivo de configuracion
    domain,port,malwareWindowsPath,malwarePath,malwareName = loadCfg()
    malwarePids = ['5168','7552','10']
    # Obtenemos la informacion de un proceso en especifico
    processInfo = pidInfo(malwarePids)
     # Acerca del proceso verificamos el uso de CPU y la RAM consumida por este.
    #print processInfo
    highProcesses = procAlert(processInfo)
    # Obtenemos los diccionarios relacionados a HKLM y HKCU, en cada uno tenemos las caracteristicas de las llaves.
    dic_HKLM = keysHKLM()
    #print dic_HKLM
    dic_HKCU = keysHKCU()
    #print dic_HKCU
    try:
        # Listas que contiene los indices donde se encontraron la cadena identificada donde se almacena el malware dentro de la llave de registro.
        match_HKLM,match_HKCU = find_key_with_exe(dic_HKLM,dic_HKCU,highProcesses)
        # Proceso que se realizara cuando se identifica una concidencia en las llaves
        keyAlert(match_HKLM,match_HKCU)
    except (TypeError, AttributeError):
        pass
    
    # Buscamos archivos bat en el directorio donde normalmete se alohja el malware
    findFiles(malwareWindowsPath)
    # Obtenemos una lista de los proceso ejecutados.
    # listOfRunningProcess = getListOfProcess()
    # Listamos los 10 procesos con mayor uso de CPU 
    # for i in listOfRunningProcess[:10]:
      #  print i
    # Buscamos un especifico PID y regresamos una lista con sus detalles.
    # processInfo = findPID(malwarePid)
    