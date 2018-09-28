# This python file uses the following encoding: utf-8
import binascii

Base64ToBinario = [
    ('A', '000000'),
    ('B', '000001'),
    ('C', '000010'),
    ('D', '000011'),
    ('E', '000100'),
    ('F', '000101'),
    ('G', '000110'),
    ('H', '000111'),
    ('I', '001000'),
    ('J', '001001'),
    ('K', '001010'),
    ('L', '001011'),
    ('M', '001100'),
    ('N', '001101'),
    ('O', '001110'),
    ('P', '001111'),
    ('Q', '010000'),
    ('R', '010001'),
    ('S', '010010'),
    ('T', '010011'),
    ('U', '010100'),
    ('V', '010101'),
    ('W', '010110'),
    ('X', '010111'),
    ('Y', '011000'),
    ('Z', '011001'),
    ('a', '011010'),
    ('b', '011011'),
    ('c', '011100'),
    ('d', '011101'),
    ('e', '011110'),
    ('f', '011111'),
    ('g', '100000'),
    ('h', '100001'),
    ('i', '100010'),
    ('j', '100011'),
    ('k', '100100'),
    ('l', '100101'),
    ('m', '100110'),
    ('n', '100111'),
    ('o', '101000'),
    ('p', '101001'),
    ('q', '101010'),
    ('r', '101011'),
    ('s', '101100'),
    ('t', '101101'),
    ('u', '101110'),
    ('v', '101111'),
    ('w', '110000'),
    ('x', '110001'),
    ('y', '110010'),
    ('z', '110011'),
    ('0', '110100'),
    ('1', '110101'),
    ('2', '110110'),
    ('3', '110111'),
    ('4', '111000'),
    ('5', '111001'),
    ('6', '111010'),
    ('7', '111011'),
    ('8', '111100'),
    ('9', '111101'),
    ('+', '111110'),
    ('/', '111111')]

import base64
import secrets
import codecs


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

    def formarBloques(self, textoInB64, size):

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
            texto += elemento

        return texto

    def cifrar(self, mensaje, clave):

        #Se genera un hexadecimal de 4 Bytes random que será nuestro Vector de Inicialización
        self.IV = self.generarIV()

        #Pasar el mensaje de texto claro a base64 y luego dividirlo en bloques de tamaño 4
        mensajeB64 = self.textToBase64(mensaje)
        self.bloques = self.formarBloques(mensajeB64, self.sizeBloque)

        #Pasar la clave de texto claro a base64 y luego obtener 10 claves que se utilizarán en las 10 iteraciones
        claveB64 = self.textToBase64(clave)
        self.claves = self.generarClaves(claveB64)
        #Pasar el bloque 1 del mensaje a hexadecimal
        mensajeHex = self.textToHex(self.bloques[0])

        #Ciclo para realizar las 10 iteraciones con todos los bloques del mensaje
        for i in range (0, 1, 1):
            # Aplicar XOR con el el IV
            xorMensajeAndIV = self.calcularXOR(mensajeHex, self.IV)

            # Realizar la transposición del bloque.
            mensajeHexTranspuesto = self.transponerByte(xorMensajeAndIV)
            # Aplicar XOR del mensaje transpuesto con la clave generada K1.
            xorMsgTransAndK1 = self.calcularXOR(mensajeHexTranspuesto, self.textToHex(self.claves[i]))
            # Realizar un corrimiento de 1 byte hacia la izquierda
            msgCorridoToLeft = self.correrByteIzquierda(xorMsgTransAndK1)
            #Guardar el resultado en la lista de bloques
            self.bloques[0] = msgCorridoToLeft

            for j in range (1, len(self.bloques), 1):
                # Pasar el bloque 1 del mensaje a hexadecimal y aplicar XOR con el el IV

                mensajeHex = self.textToHex(self.bloques[j])
                xorMensajeAndIV = self.calcularXOR(mensajeHex, self.listaToString(self.bloques[j-1]))

                # Realizar la transposición del bloque.
                mensajeHexTranspuesto = self.transponerByte(xorMensajeAndIV)
                # Aplicar XOR del mensaje transpuesto con la clave generada K1.
                xorMsgTransAndK1 = self.calcularXOR(mensajeHexTranspuesto, self.textToHex(self.claves[j]))
                # Realizar un corrimiento de 1 byte hacia la izquierda
                msgCorridoToLeft = self.correrByteIzquierda(xorMsgTransAndK1)
                self.bloques[j] = msgCorridoToLeft
        cipherText = ""
        for i in range (len(self.bloques)):
            cipherText += self.listaToString(self.bloques[i])
        return cipherText

'''Ejemplo de uso'''
tbca = TBCA()
print(tbca.cifrar("Hola", "clave1234"))