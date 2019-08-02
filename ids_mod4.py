# python -m pip install psutil

print("[*] Iniciando IDS...")
print ('[*] Cargando bibliotecas...')
# Para trabajar con el registro en Windows
from _winreg import *
# Para trabajar con los procesos de Windows
import psutil
# Para leer la configuracion de un archivo.
import ConfigParser
# Para buscar contenido especifico dentro de las llaves de Registro.
import re
import os
import datetime
# para mostrar mensajes al usuario cuando se detecte una amenaza
import ctypes
#
from socket import gethostbyname
#
from scapy.all import *

c = 1
#from virustotalAPI import *
# do_scan("cfb7df0446eecab2dbd64e26e652c5c8a3dd57028e549fbf0a1e50216f99f49b",str(proc.values()[1]))
IoClistDetected = []

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
def keyAlert(match_HKLM,match_HKCU,dic_HKLM=None,dic_HKCU=None):
    global IoClistDetected
    keys = []
    if not match_HKLM:
        #print "Todo Normal en HKLM"
        pass
    else:
        for i in match_HKCU:
            llave = dic_HKCU.values()[i][0]
            # Se realizara el proceso para la ALERTA despues de detectar una llave igual a la del malware
            #print "ALERTA: se encontro una llave en HKLM"
            key = "\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "+llave
            keys.append(key)
    if not match_HKCU:
        #print "Todo Normal en HKCU"
        pass
    else:
        for i in match_HKCU:
            llave = dic_HKCU.values()[i][0]
            # Se realizara el proceso para la ALERTA despues de detectar una llave igual a la del malware
            #print "ALERTA: se encontro una llave en HKCU"
            key = "\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run "+llave
            keys.append(key)
    IoClistDetected.append(keys)
def procAlert(processInfo):
    global IoClistDetected
    highProcesses = []
    for proc in processInfo:
        #print 'proceso:'
        #print proc
        cpuAlert= False
        ramAlert = False
        # Si el proceso cosume un % mayor a 70% de CPU
        if proc['cpu_percent'] >= 0.0:
            #print "Alerta de aumento de CPU en el proceso: %s con PID %s consumo CPU: %.2f   " %(proc.values()[3],proc.values()[2],proc.values()[4])
            cpuAlert = True
        # Si el proceso cosume mas de 350MB de memoria RAM
        if proc['vms'] >= 350.0:
            #print "Alerta de aumento de CPU en el proceso: %s con PID %s consumo RAM: %.2f Mb" %(proc.values()[3],proc.values()[2],proc.values()[0])
            ramAlert = True
        if cpuAlert:
            highProcesses.append(proc)
            IoClistDetected.append(proc)
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
def findFiles(highProcesses):
    global IoClistDetected
    for proc in highProcesses:
        path = proc['exe'][:(len(proc['name'])*-1)]
        #print path
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
                #print match.group(2)
                exeFiles.append(match.group(2))
            IoClistDetected.append(file)
    return malwareFilesBat,exeFiles

def bitacora(IoClistDetected):
    '''
        Funcion que creara una bitacora, donde almacenara los IoC hayados en la pieza de malware de minado.
    '''
    if len(IoClistDetected) >= 2:
        messageBox()
        bitacora = open("bitacoraIDS.txt","a")
        try:
            # Damos formato al diccionario que tiene los detalles del ejecutable encontrado.
            date_process = datetime.now()
            print '1'
            details = str(date_process)+" ... "+"WARNING"
            print '2'
            detailProcess = IoClistDetected[0]
            print '3'
            details += " ... "+str(detailProcess.values()[3])+" ... "+str(detailProcess.values()[1])+" ... "+str(detailProcess.values()[2])+"PID"+" ... "+str(detailProcess.values()[4])+"CPU"+" ... "+str(detailProcess.values()[0])+"MB RAM"
            print '4'
            # Agregamos cada llave de registro que fue encontrada
            for llave in IoClistDetected[1]:
                details += " ... "+llave
            # Agregamos los archivos relacionados a la pieza de malware encontrados
            print '5'
            details += " ... "+str(IoClistDetected[2])
            print '6'
            bitacora.write(details+"\n")  
            print '7'
        except  (TypeError, AttributeError,IndexError) as e:
            print e
        bitacora.close()
    else:
        pass

def messageBox():
    MessageBox = ctypes.windll.user32.MessageBoxA
    MessageBox(None, 'Se detecto una amenaza en tu equipo revisa tu bitacora de IDS', 'WARNING', 48)


def get_pid(dst, dstport):
    '''
    Funcion que obtiene el PID de un proceso a partir de su actividad en red
    Recibe: dst, que es la IP destino; dstport, que es el puerto destino
    Devuelve: El PID del proceso identificado
    '''
    global dic
    pids = [x.pid for x in psutil.process_iter()]
    for pid in pids:
        try:
            proc = psutil.Process(pid).connections()
            if len(proc) > 0:
                for conn in range(len(proc)):
                    if len(proc[conn].raddr) > 0:
                        ip = proc[conn].raddr.ip #str
                        dport = str(proc[conn].raddr.port) #int
                        if ip == dst and dport == dstport and pid != 0:
                            print 'Se detecto IP destino y puerto sospechosos: %s:%s del proceso con PID:%s'%(ip,dport,str(pid))
                            return pid
        except Exception as e:
            print e
    return 0


def crea_regla(domains,ports):
    print '[*] Creando reglas de acuerdo al archivo de configuracion'
    ips =[]
    regla = ''
    domains = domains.replace(' ','')
    ports = ports.replace(' ','')
    dominios = domains.split(',')
    puertos = ports.split(',')
    del domains
    del ports
    for i in range(len(dominios)):
        ips.append(gethostbyname(dominios[i]))
    #print ips
    for ip in ips:
        regla += '(host ' + ip + ' and (' + 'port ' + ' or port '.join(puertos) + ')) or '
    print '[*] Reglas aplicadas en el filtro: '
    print regla[:-4]
    return regla[:-4]


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

def print_packet(packet):
    '''
    Funcion que se ejecuta cada vez que llega un paquete
    Recibe: paquete, el paquete a analizar
    Devuelve: None
    '''
    global c
    try:
        ip_layer = packet.getlayer(IP)
        print("[!] Paquete {n}: {src}:{sport} -> {dst}:{dport}".format(n=c,src=ip_layer.src, sport=ip_layer.sport ,dst=ip_layer.dst, dport=ip_layer.dport))
        try:
            print(packet[Raw].load)
        except Exception:
            pass
        malwarePids = get_pid(str(ip_layer.dst),str(ip_layer.dport))
        if malwarePids != 0:
            """
            Aqui van las funciones de Pedro
            """
            #print "Buscando proceso"
            processInfo = pidInfo([malwarePids])
            #print processInfo
            # Acerca del proceso verificamos el uso de CPU y la RAM consumida por este.
            highProcesses = procAlert(processInfo)
            #print highProcesses
            # Obtenemos los diccionarios relacionados a HKLM y HKCU, en cada uno tenemos las caracteristicas de las llaves.
            dic_HKLM = keysHKLM()
            dic_HKCU = keysHKCU()
            try:
                # Listas que contiene los indices donde se encontraron la cadena identificada donde se almacena el malware dentro de la llave de registro.
                match_HKLM,match_HKCU = find_key_with_exe(dic_HKLM,dic_HKCU,highProcesses)
                # Proceso que se realizara cuando se identifica una concidencia en las llaves
                keyAlert(match_HKLM,match_HKCU,dic_HKLM,dic_HKCU)
                # Buscamos archivos bat en el directorio donde normalmete se alohja el malware
                findFiles(highProcesses)
            except (TypeError, AttributeError):
                pass
            
            
        c += 1
    except Exception as e:
        print(e)


if __name__== "__main__":
    # Obtenemos los parametros desde un archivo de configuracion
    domain,port,malwareWindowsPath,malwarePath,malwareName = loadCfg()
    regla = crea_regla(domain,port)
    print("\n[*] Escaneando la red...")

    #sniff(filter="host 132.248.181.220 and (port 443 or port 80)", prn=print_packet)
    sniff(filter=regla, prn=print_packet)
    
    print("[*] Deteniendo IDS")
    #bitacora(IoClistDetected)
    for x in range(0,len(IoClistDetected),3):
    	print [IoClistDetected[x],IoClistDetected[x+1]]
    	bitacora([IoClistDetected[x],IoClistDetected[x+2]])

    #malwarePids = ['5168','7080','10']
        # Obtenemos la informacion de un proceso en especifico

        # Obtenemos una lista de los proceso ejecutados.
        # listOfRunningProcess = getListOfProcess()
        # Listamos los 10 procesos con mayor uso de CPU 
        # for i in listOfRunningProcess[:10]:
        #  print i
        # Buscamos un especifico PID y regresamos una lista con sus detalles.
        # processInfo = findPID(malwarePid)
    

