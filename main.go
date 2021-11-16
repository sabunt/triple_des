//TripleDES
// ./main.go

package main

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
)

func main() {
	textForParse := flag.String("text", "", "Text for parsing")
	key := flag.String("key", "", "key for encrypt/decrypt")
	decrypt := flag.Bool("d", false, "Value for decrypt")
	flag.Parse()

	var result string
	var err error

	if *decrypt {
		result, err = tripleDesECBDecrypt([]byte(*textForParse), []byte(*key))
	} else {
		result, err = tripleDesECBEncrypt([]byte(*textForParse), []byte(*key))
	}
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - (len(ciphertext) % blockSize) // Узнаем сколько байт еще не хватает.
	// padding := 8-(27%8) = 8-3 = 5
	padtext := bytes.Repeat([]byte{byte(padding)}, padding) // Создадим текст на то количества байт,что не хватает для деления на 8
	// padtext := []byte{5,5,5,5,5}
	return append(ciphertext, padtext...) // Добавим его в конец текста
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)                // Получаем длину слайса
	unpadding := int(origData[length-1])   //Получаем последний элемент слайса. Он и будет нам говорить сколько элементов было добавлено в слайс
	return origData[:(length - unpadding)] // Возвращаем слайс без лишних элементов
}

func tripleDesECBEncrypt(src, key []byte) (string, error) {
	block, err := des.NewTripleDESCipher(key) // делит наш ключ на три части по 8 байт и создает подключи из этих , поэтому если ваш ключ будет не равен 24 байт у вас ничего не получится
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()           // Выясним какой размер блока
	origData := PKCS5Padding(src, bs) //Доработаем наш текст чтобы он стал валидным для этого способа шифрования
	if len(origData)%bs != 0 {
		return "", errors.New("need a multiple of the blocksize")
	}

	out := make([]byte, len(origData)) //Создадим слайс для заполнения защифрованных данных
	dst := out                         //Используем такую конструкцию вместо append

	for len(origData) > 0 {
		block.Encrypt(dst, origData[:bs]) // Encrypt шифрует блок origData[:bs] в dst.
		origData = origData[bs:]          // Уменьшаем длину строки на размер блока
		dst = dst[bs:]                    // Уменьшаем длину референса слайса на размер блока
	}

	// Вариант с append
	// var out []byte
	// dst := make([]byte, bs)
	// iterationSteps := len(origData) / bs
	// for i := 0; i < iterationSteps; i++ {
	//   block.Encrypt(dst, origData[:bs])
	//   origData = origData[bs:]
	//   out = append(out, dst...)
	// }

	return hex.EncodeToString(out), nil
}

func tripleDesECBDecrypt(src, key []byte) (string, error) {
	src, err := hex.DecodeString(string(src))
	if err != nil {
		return "", err
	}

	block, err := des.NewTripleDESCipher(key) // делим наш ключ на три части по 8 байт и создает подключи из этих, поэтому если ваш ключ будет не равен 24 байт у вас ничего не получится
	if err != nil {
		return "", err
	}
	bs := block.BlockSize() // Выясним какой размер блока
	if len(src)%bs != 0 {
		return "", errors.New("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(src)) //Создадим слайс для заполнения расшифрованных данных
	dst := out                    //Используем такую конструкцию вместо append
	for len(src) > 0 {
		block.Decrypt(dst, src[:bs]) // Decrypt дешифрует блок origData[:bs] в dst.
		src = src[bs:]               // Уменьшаем длину строки на размер блока
		dst = dst[bs:]               // Уменьшаем длину слайса на размер блока
	}
	out = PKCS5UnPadding(out) // Убираем лишние символы
	return string(out), nil
}
