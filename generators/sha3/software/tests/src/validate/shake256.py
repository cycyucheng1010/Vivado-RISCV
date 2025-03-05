from Crypto.Hash import SHAKE256

def generate_shake256(input_data, output_length):
    # 初始化 SHAKE256 哈希对象
    shake = SHAKE256.new()
    shake.update(input_data)  # 输入数据
    return shake.read(output_length)  # 生成指定长度的输出

if __name__ == "__main__":
    # 设置测试数据
    input_data = bytes([0] * 150)  # 输入 150 个字节，值为 0
    output_length = 64  # 输出 64 字节

    # 生成 SHAKE256 输出
    result = generate_shake256(input_data, output_length)

    # 将结果转换为十进制数组
    decimal_result = [b for b in result]
    print("SHAKE256 output (decimal):")
    print(decimal_result)
