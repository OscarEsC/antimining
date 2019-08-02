#   Makefile
#   python -m pip install requests
#   python -m pip install virustotal-api

import requests
import os.path


virustotal_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
virustotal_scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
virustotal_rescan_url = 'https://www.virustotal.com/vtapi/v2/file/rescan'


def print_report_result(json_result):
    """
        Funcion para mostrar los resultados de un reporte en
        Virus Total
    """
    print  'identificador del archivo:  ' + str(json_result['resource'])
    print 'enlace permanente:  ' + str(json_result['permalink'])
    print 'dia analizado:  ' + str(json_result['scan_date'])
    print 'SHA256:  ' + str(json_result['sha256'])
    print 'detecciones:  ' + str(json_result['positives'])
    print 'escaneos totales:  ' + str(json_result['total'])
    if json_result['positives'] > 0 :
        print 'Este archivo es malicioso'
    else:
        print 'Este archivo no es malicioso'


def get_report (vt_apykey, resource):
    """
        Funcion para obtener un reporte completo de un archivo ya existente en Virus Total
        Recibe la key y el identificador del archivo 'resourse'
    """
    #En los parametros de la consulta se ponen la llave y el identificador
    params = {'apikey': vt_apykey, 'resource': resource}
    response = requests.get(virustotal_report_url, params=params)

    print_report_result(response.json())

def print_scan_result(json_result):
    print 'enlace permanente:  ' + str(json_result['permalink'])
    print 'identificador del archivo:  ' + str(json_result['resource'])
    print 'SHA256:  ' + str(json_result['sha256'])
    print 'Visita el enlace para mas informacion o puedes obtener'
    print 'el reporte usando el identificador del archivo'

def do_scan(vt_apykey, filename):
    """
        Funcion para subir a Virus Total un archivo max 32MB
        para ser analizado
        Recibe la key y el nombre del archivo a subir
        No resulta un reporte completo.
    """
    try:
        params = {'apikey': vt_apykey}
        files = {'file': ('myfile.exe', open(filename, 'rb'))}
        response = requests.post(virustotal_scan_url, files=files, params=params)
        print_scan_result(response.json())

    except IOError:
        print('No se tienen permisos para leer el archivo ' + filename + ' o no existe')

def do_rescan(vt_apykey, resource):
    """
        Funcion para hacer un re-escaneo de un archivo subido previamente
        Recibe la key y el identificador del archivo 'resource'
        No resulta un reporte completo
    """
    params = {'apikey': vt_apykey, 'resource': resource}
    response = requests.post(virustotal_rescan_url, params=params)
    print_scan_result(response.json())


