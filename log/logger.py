def preprocessing_registry(lines):
    """Metodo encargado de preprocesar los registros del log
    :Parametros:
        lines : list
            lista de lineas del archivo log
    :Return: 
        msgs : list
            lista de lineas preprocesadas del log
    """
    msgs = []
    for line in lines:
        line = line.split('>')
        if len(line) != 4:
            continue
        msgs.append({'fecha':line[0],'msg':line[1],'ciphertext':line[2],'plaintext':line[3]})
    return msgs

def get_registry():
    """Metodo encarga de obtener los registro del archivo log
    :Parametros:
    :Return: 
        msgs : list
            lista de lineas preprocesadas del log
    """
    with open('./info_cifrada.log','r') as f:
        lines = f.readlines()
    return preprocessing_registry(lines)

def log_info(params):
    """metodo que escribe en un archivo de log
    :Parametros:
        params : any 
            parametro a escribit en el archivo
    :Return: 
    """
    with open('./info_cifrada.log','a') as f:
        f.write('\n'+params)
