Ý tưởng bỏ phiếu kín sử dụng Homomorphic Encryption

1. Mục tiêu

Cho phép kiểm phiếu mà hệ thống không cần giải mã từng lá phiếu riêng lẻ.

Mỗi phiếu được mã hóa tại thiết bị của người bỏ phiếu. Máy chủ chỉ cộng các ciphertext và chỉ kết quả tổng cuối cùng mới được giải mã.

2. Cách biểu diễn phiếu

Ví dụ có 3 ứng viên:

Ứng viên A → [1, 0, 0]
Ứng viên B → [0, 1, 0]
Ứng viên C → [0, 0, 1]

Mỗi vector được mã hóa bằng public key của cuộc bỏ phiếu.

3. Luồng xử lý đơn giản

flowchart LR
    A["Người bỏ phiếu<br/>chọn ứng viên"] --> B["Mã hóa phiếu<br/>bằng public key"]
    B --> C["Hòm phiếu điện tử<br/>lưu ciphertext"]
    C --> D["HE Tally Service<br/>cộng các phiếu mã hóa"]
    D --> E["Encrypted total"]
    E --> F["Hội đồng giải mã<br/>threshold decryption"]
    F --> G["Kết quả cuối cùng"]

4. Ví dụ kiểm phiếu

Phiếu 1: A → [1, 0, 0]
Phiếu 2: C → [0, 0, 1]
Phiếu 3: A → [1, 0, 0]

Enc([1,0,0])
+ Enc([0,0,1])
+ Enc([1,0,0])
= Enc([2,0,1])

Sau khi giải mã kết quả tổng:

A = 2
B = 0
C = 1

Máy chủ kiểm phiếu không biết từng người đã chọn ai.

5. Các thành phần cần bổ sung ngoài HE

HE chỉ bảo vệ nội dung phiếu và hỗ trợ cộng phiếu mã hóa. Một hệ thống bỏ phiếu hoàn chỉnh còn cần:

Xác thực người bỏ phiếu và ngăn bỏ phiếu nhiều lần.

Zero-knowledge proof để chứng minh mỗi phiếu hợp lệ, ví dụ chỉ chọn đúng một ứng viên.

Threshold key để không một quản trị viên nào tự giải mã được phiếu.

Chữ ký số và audit log để phát hiện phiếu bị sửa hoặc chèn thêm.

Tách riêng hệ thống định danh khỏi hòm phiếu để bảo vệ tính ẩn danh.

Cơ chế công khai kiểm chứng kết quả.

6. Thuật toán phù hợp

Ưu tiên các scheme hỗ trợ số nguyên chính xác:

Paillier cho phép cộng đồng cấu đơn giản.

BFV hoặc BGV cho phép tính toán số nguyên và SIMD packing.

Threshold Paillier hoặc threshold BFV/BGV phù hợp khi nhiều bên cùng giữ quyền giải mã.

Không nên ưu tiên CKKS cho kiểm phiếu chính thức vì CKKS sử dụng số gần đúng.

7. Kết luận

HE có thể được dùng để xây dựng cơ chế kiểm phiếu kín:

Encrypt individual votes
        ↓
Aggregate ciphertexts
        ↓
Threshold decrypt aggregate only
        ↓
Publish and independently verify final totals

Kế hoạch kỹ thuật chi tiết cho phiên bản nhân viên chọn A/B/C và cơ chế chống bỏ phiếu hai lần
bằng trạng thái mã hóa nằm trong `IMPLEMENTATION_PLAN.md`.
