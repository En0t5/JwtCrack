package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// 从文件中读取密码列表
func readKeysFromFile(filePath string) ([]string, error) {
	var passwords []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open password file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read password file: %v", err)
	}

	return passwords, nil
}

// Base64 解码函数
func decodeBase64(input string) ([]byte, error) {
	// 对 Base64 编码的密钥进行解码
	return base64.StdEncoding.DecodeString(input)
}

// 解析并验证 JWT
func parseJWT(tokenString string, secretKeyString string) (*jwt.Token, error) {

	secretKey := []byte(secretKeyString)

	// 将传入的 JWT 字符串解析为 jwt.Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否符合预期，这里我们只允许使用 HMAC 署名算法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 返回 secretKey 用于签名验证
		return secretKey, nil
	})
	return token, err
}

// 解析并验证 JWT
func parseJWTKeyBase64(tokenString string, secretKeyString string, decodeKey bool) (*jwt.Token, error) {
	var secretKey []byte
	var err error
	// 如果 -jjwt 参数为 true，首先尝试 Base64 解码密钥
	if decodeKey {
		// 去除所有非 Base64 字符
		re := regexp.MustCompile("[^A-Za-z0-9+/=]")
		secretKeyString = re.ReplaceAllString(secretKeyString, "")

		padding := 4 - len(secretKeyString)%4
		if padding != 4 {
			secretKeyString += strings.Repeat("=", 2)
		}
		secretKey, err = decodeBase64(secretKeyString)
		if err != nil {
			//return nil, fmt.Errorf("failed to base64 decode key: %s\n", secretKeyString)
			//fmt.Printf("failed to base64 decode key: %s\n", secretKeyString)
		}
		//secretKey = string(decodedKey) // 使用解码后的密钥
	} else {
		secretKey = []byte(secretKeyString)
	}

	// 将传入的 JWT 字符串解析为 jwt.Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否符合预期，这里我们只允许使用 HMAC 署名算法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 返回 secretKey 用于签名验证
		return secretKey, nil
	})
	return token, err
}

// 解码 JWT 的 payload 部分
func decodeJWT(tokenString string) (map[string]interface{}, error) {
	// 将 JWT 字符串分割为三部分：Header, Payload, Signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT token")
	}

	// 解码 Payload 部分（Base64URL 解码）
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, err
	}

	// 解析为一个 map
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return nil, err
	}

	return payloadMap, nil
}

// Base64URL 解码函数
func decodeBase64URL(input string) ([]byte, error) {
	// 补齐输入的 Base64URL 字符串，使其长度为 4 的倍数
	padding := 4 - len(input)%4
	if padding != 4 {
		input += strings.Repeat("=", padding)
	}

	// 将 Base64URL 转为标准 Base64
	input = strings.ReplaceAll(input, "-", "+")
	input = strings.ReplaceAll(input, "_", "/")

	return base64.StdEncoding.DecodeString(input)
}

func main() {
	// 获取命令行参数
	tokenPtr := flag.String("token", "", "JWT Token to decode")
	Keys := flag.String("keys", "keys.txt", "Jwt Secret Keys")
	isKeyBase64 := flag.Bool("base64", false, "If true, Default decode and Base64 decode the secret key before validating the JWT(Default configuration for Java JJWT)")
	flag.Parse()

	if *tokenPtr == "" {
		log.Fatal("JwtCrack -token exxxx.exxx.xxxx \nJwtCrack -base64 true -token exxxx.exxx.xxxx")
	}

	// 从文件中读取密码列表
	secretKeys, err := readKeysFromFile(*Keys)
	if err != nil {
		log.Fatalf("Failed to read passwords: %v", err)
	}

	// 批量尝试密码
	for _, secretKey := range secretKeys {
		// 尝试用当前密码解码和验证 JWT
		token, err := parseJWT(*tokenPtr, secretKey)
		if err != nil {
			// 如果解析失败，跳过
			continue
		}

		// 验证签名
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println("Valid Token Found!")
			fmt.Println("Secret Key: ", secretKey)
			fmt.Println("Claims:", claims)

			return // 找到有效的密钥后退出
		}
	}

	// 同时启动默认解密和jjwt的解密爆破
	if *isKeyBase64 {
		// 批量尝试密码
		for _, secretKey := range secretKeys {
			// 尝试用当前密码解码和验证 JWT
			token, err := parseJWTKeyBase64(*tokenPtr, secretKey, *isKeyBase64)
			if err != nil {
				// 如果解析失败，跳过
				continue
			}

			// 验证签名
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				fmt.Println("Valid Token Found!")
				fmt.Println("Base64 Secret Key: ", secretKey)
				fmt.Println("Claims:", claims)
				return // 找到有效的密钥后退出
			}
		}
	}

	// 如果没有找到有效的密钥
	log.Fatal("No valid JWT found with the given password list.")
}
