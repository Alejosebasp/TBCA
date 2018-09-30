# This python file uses the following encoding: utf-8

import base64
import secrets


class TBCA:
    """ Clase para cifrar y descifrar con el algoritmo TBCA\n
        :author: Alejandro Alejo.\n
        :version: 1.0
        :contact: alsalejopa@unal.edu.co
    """

    sizeBloque = 4
    sizeClave = 4

    def __init__(self):
        self.bloques = []
        self.claves = []
        self.cipherText = ""
        self.bloquesCipherText = []
        self.mensajeDescifrado = []

    def generarIV(self):
        IV_hex = secrets.token_hex(4)
        return IV_hex

    def textToHex(self, mensaje):

        mensajeHex = mensaje.encode('utf-8')
        return mensajeHex.hex()

    def textToBase64(self, mensaje):

        mensajeB64 = base64.b64encode(bytes(mensaje, 'utf-8'))

        return mensajeB64.decode("utf-8")

    def calcularXOR(self, stringHex1, stringHex2):

        resultado = []
        for i in range(0, self.sizeBloque * 2, 2):
            xor = int(hex(int(stringHex1[i:i + 2], 16)), 16) ^ int(hex(int(stringHex2[i:i + 2], 16)), 16)
            resultado.append(str(hex(xor))[2:])

        return resultado

    def crearBloquesParaCifrar(self, textoInB64, size):

        bloques = []
        for i in range(0, len(textoInB64), size):
            bloques.append(textoInB64[i + 0] + textoInB64[i + 2] + textoInB64[i + 1] + textoInB64[i + 3])
        return bloques

    def generarClaves(self, claveB64):

        claves = []
        for i in range (0, 50, 5):
            claveB64 += claveB64
            claves.append(claveB64[i:i+4])
        return claves

    def transponerByte(self, bloque):
        """Función para transponer los 4 bits de mayor peso de cada bloque al inicio
        y los 4 bits de menor peso de cada bloque al final.\n
        :param bloque: lista con los bytes en hexadecimal del bloque.\n
        :type bloque: list \n
        :return: String con los valores hexadecimales transpuestos. \n
        :rtype: str"""

        bytesPares = []
        bytesImpares = []

        for hexa in bloque:
            if (len(hexa) == 1):
                bytesPares.append(0)
                bytesImpares.append(hexa)
                continue

            for i in range(0, len(hexa), 1):
                if (i % 2 == 0):
                    bytesPares.append(hexa[i])
                else:
                    bytesImpares.append(hexa[i])

        result = ""
        paresImpares = bytesPares + bytesImpares
        for i in range (0, len(paresImpares), 2):
            result += (str(paresImpares[i]) + str(paresImpares[i+1]))

        return result

    def correrByteIzquierda(self, cadenaHex):

        temp = cadenaHex[0]
        for i in range(0, len(cadenaHex)-1, 1):
            cadenaHex[i] = cadenaHex[i+1]
        cadenaHex[-1] = temp

        return cadenaHex

    def listaToString(self, listaHex):

        texto = ""
        for elemento in listaHex:
            if (len(elemento) == 1):
                texto += '0'+elemento
            else:
                texto += elemento

        return texto

    def stringToList(self, cadenaEnHexa):
        lista = []

        for i in range(0, len(cadenaEnHexa), 2):
            lista.append(cadenaEnHexa[i:i+2])
        return lista

    def cifrar(self, mensaje, clave):

        #Se genera un hexadecimal de 4 Bytes random que será nuestro Vector de Inicialización
        self.IV = self.generarIV()

        #Pasar el mensaje de texto claro a base64 y luego dividirlo en bloques de tamaño 4
        mensajeB64 = self.textToBase64(mensaje)
        self.bloques = self.crearBloquesParaCifrar(mensajeB64, self.sizeBloque)


        #Pasar la clave de texto claro a base64 y luego obtener 10 claves que se utilizarán en las 10 iteraciones
        claveB64 = self.textToBase64(clave)
        self.claves = self.generarClaves(claveB64)
        print("Claves en b64: ", self.claves)
        print("Bloques: ", self.bloques)
        #Ciclo para realizar las 10 iteraciones con todos los bloques del mensaje
        print("IV: ", self.IV)
        for clave in self.claves:
            for i in range (0, len(self.bloques), 1):

                # Pasar el bloque 1 del mensaje a hexadecimal
                if  (clave == self.claves[0]):
                    mensajeHex = self.textToHex(self.bloques[i])
                    self.bloques[i] = mensajeHex

                # Aplicar XOR con el el IV
                if (i == 0):
                    xorMensajeAndIV = self.calcularXOR(self.bloques[i], self.IV)
                else:
                    xorMensajeAndIV = self.calcularXOR(self.bloques[i], self.bloques[i-1])

                # Realizar la transposición del bloque.
                mensajeHexTranspuesto = self.transponerByte(xorMensajeAndIV)
                # Aplicar XOR del mensaje transpuesto con la clave generada K1.
                claveHexa = self.textToHex(clave)
                print("Clave hexa: ", claveHexa)
                xorMsgTransAndKi = self.calcularXOR(mensajeHexTranspuesto, claveHexa)
                # Realizar un corrimiento de 1 byte hacia la izquierda
                msgShiftLeft = self.correrByteIzquierda(xorMsgTransAndKi)
                #Guardar el resultado en la lista de bloques
                self.bloques[i] = self.listaToString(msgShiftLeft)
                print("Bloques: ", self.bloques)

        self.cipherText = self.listaToString(self.bloques)

        return self.cipherText

    def crearBloquesParaDescifrar(self, cadenaStrinHexa):
        bloquesCipherText = self.stringToList(cadenaStrinHexa)
        bloques = []
        for i in range(0, len(bloquesCipherText), self.sizeBloque):
            bloques.append(bloquesCipherText[i] + bloquesCipherText[i+1]
                           + bloquesCipherText[i+2] + bloquesCipherText[i+3])
        bloques.reverse()
        return bloques

    def correrByteDerecha(self, cadenaHex):
        """Función para correr la cadena de hexadecimales un byte hacia la derecha.\n
        :param cadenaHex: Lista con los hexadecimales del bloque que se desea correr.\n
        :type cadenaHex:list\n
        :return: Lista actualizada con el corrimiento de 1 byte.\n
        :rtype: str
        """

        temp = cadenaHex[-1]
        for i in range(len(cadenaHex)-1, 0, -1):
            cadenaHex[i] = cadenaHex[i-1]
        cadenaHex[0] = temp
        return self.listaToString(cadenaHex)

    def invTransponerByte(self, listaBloque):

        """

        :param listaBloque:
        :return: cadena de texto transpuesta
        :rtype: str
        """

        bytesPares = []
        bytesImpares = []
        cadenaTranspuesta = ""

        for hexa in listaBloque:
            if (listaBloque.index(hexa) % 2 == 0):
                bytesPares.append(hexa)
            else:
                bytesImpares.append(hexa)

        hexa2 = ""
        for hexa in bytesPares:
            for i in range(0, len(hexa), 1):
                if (i % 2 == 0):
                    cadenaTranspuesta += hexa[i]
                else:
                    hexa2 += hexa[i]
        cadenaTranspuesta += hexa2
        hexa2 = ""
        for hexa in bytesImpares:
            for i in range(0, len(hexa), 1):
                if (i % 2 == 0):
                    cadenaTranspuesta += hexa[i]
                else:
                    hexa2 += hexa[i]
        cadenaTranspuesta += hexa2
        return cadenaTranspuesta

    def hexToText(self, cadenaHex):
        return (bytes.fromhex(cadenaHex).decode('ISO-8859-1'))


    def descifrar(self, cipherTextInHexa, clave):
        #Pasar el string a una lista de bytes hexadecimales y crear los bloques para descifrar
        self.bloquesCipherText = self.crearBloquesParaDescifrar(cipherTextInHexa)

        print("IV: ", self.IV)

        # Pasar la clave de texto claro a base64 y luego obtener 10 claves que se utilizarán en las 10 iteraciones
        claveB64 = self.textToBase64(clave)
        #self.claves = self.generarClaves(claveB64)
        self.claves.reverse()

        print("Claves inversas: ", self.claves)

        print("Bloques para decifrar: ", self.bloquesCipherText)

        for clave in self.claves:
            for i in range(len(self.bloquesCipherText)):

                # Realizar la traslación de 1 byte hacia la derecha del cipherText
                shiftBytesRight = self.correrByteDerecha(self.stringToList(self.bloquesCipherText[i]))
                # Aplicar el XOR del cipher Text con la clave para
                claveEnHexa = self.textToHex(clave)
                print("Clave en Hexa: ", claveEnHexa)
                xorShiftBytesRightAndKi = self.calcularXOR(shiftBytesRight, claveEnHexa)

                # Aplicar la función inversa de TransponerByte
                cipherTextTranspuesto = self.invTransponerByte(xorShiftBytesRightAndKi)

                if (i == len(self.bloquesCipherText) - 1):
                    xorTextTranspuestoAndIV = self.calcularXOR(cipherTextTranspuesto, self.IV)
                else:
                    xorTextTranspuestoAndIV = self.calcularXOR(cipherTextTranspuesto, self.bloquesCipherText[i+1])

                self.bloquesCipherText[i] = self.listaToString(xorTextTranspuestoAndIV)
                print("Bloques para decifrar: ", self.bloquesCipherText)


        return self.mensajeDescifrado


'''Ejemplo de uso'''
tbca = TBCA()
mensaje = "Hola"
clave = "clave1234"
#IV = tbca.generarIV()
cipherText = tbca.cifrar(mensaje, clave)
print("Cifrado: ", cipherText)

mensajedescifrado = tbca.descifrar(cipherText, clave)
print("decifrado: ", mensajedescifrado)