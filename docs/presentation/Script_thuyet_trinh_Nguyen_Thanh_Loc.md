# Kịch bản thuyết trình đồ án Website Scam / Phishing Detector

**Người trình bày:** Nguyễn Thành Lộc — MSSV 25410244  
**Môn học:** Kỹ thuật lập trình Python — UIT  
**Sử dụng cùng:** Bộ PowerPoint 21 slide đã tạo. Slide 1–19 là phần trình bày chính, slide 20–21 dùng khi trao đổi.

Kịch bản hướng đến khoảng **15–18 phút**, tùy tốc độ nói và thời gian thao tác demo. Các đoạn trong ngoặc vuông là gợi ý thao tác, không đọc thành lời. Khi tập, nên nhớ ý chính và nói lại bằng cách của mình, không cần thuộc nguyên văn từng câu. Có thể đọc số lớn theo cách làm tròn trong lời nói, còn số chính xác đã có trên slide.

## Slide 1 — Website Scam / Phishing Detector

[Nhìn thầy cô, nói chậm ở phần giới thiệu.]

Em chào thầy cô. Em là Nguyễn Thành Lộc, mã số sinh viên 25410244.

Hôm nay em xin trình bày đồ án môn Kỹ thuật lập trình Python với đề tài Website Scam / Phishing Detector, tức là hệ thống phân tích và phát hiện dấu hiệu website lừa đảo.

Ý tưởng của đồ án là khi người dùng nhận được một đường link đáng ngờ, họ có thể đưa vào hệ thống để xem mức rủi ro và những dấu hiệu cần chú ý.

Trong phần trình bày, em sẽ đi qua cách hệ thống xử lý một URL, kết quả đánh giá mô hình, sau đó giới thiệu giao diện và những điểm còn cần cải thiện.

Trước tiên, em xin trình bày bài toán mà đồ án hướng đến.

## Slide 2 — Bài toán và mục tiêu

Ví dụ, khi nhận được một tin nhắn yêu cầu xác minh tài khoản ngân hàng, người dùng có thể thấy đường link khá giống tên ngân hàng thật. Trang mở ra cũng có giao diện đăng nhập và có HTTPS. Chỉ nhìn những yếu tố đó thì vẫn khó biết có nên nhập thông tin hay không.

Vì vậy, mục tiêu của em là xây dựng công cụ nhận một URL, kiểm tra các dấu hiệu liên quan và trả về điểm rủi ro từ 0 đến 100, kèm lời giải thích.

Hệ thống kết hợp luật kiểm tra, mô hình học máy và danh sách đen. Mỗi nguồn cung cấp một phần thông tin để hỗ trợ đánh giá.

Em cũng phân biệt rõ điểm rủi ro với xác suất của mô hình. Chẳng hạn, điểm rủi ro 80 không có nghĩa là website có đúng 80% khả năng lừa đảo.

Để thực hiện luồng xử lý này, em sử dụng các công nghệ sau.

## Slide 3 — Công nghệ và tổ chức mã nguồn

Phần web và API của đồ án dùng FastAPI. Giao diện được dựng bằng Jinja2, còn dữ liệu các lượt quét được lưu thông qua SQLAlchemy. Bản demo sử dụng SQLite, và dự án cũng có cấu hình cho PostgreSQL.

Ở phần phân tích, httpx dùng để gửi yêu cầu đến website, BeautifulSoup dùng để đọc HTML. Thông tin tên miền được tra cứu qua RDAP hoặc WHOIS. Phần học máy sử dụng scikit-learn và XGBoost.

Mã nguồn được chia theo nhiệm vụ, như thu thập dữ liệu, trích xuất thuộc tính, dự đoán và tính điểm. Cách chia này giúp em kiểm tra từng phần và thuận tiện hơn khi thay đổi một thành phần.

Dự án hiện có 16 kiểm thử tự động bằng pytest. Trong lần kiểm tra phục vụ báo cáo, cả 16 kiểm thử đều chạy thành công.

Tiếp theo là cách những thành phần này phối hợp khi nhận một URL.

## Slide 4 — Kiến trúc xử lý một URL

[Chỉ theo chiều mũi tên: hàng trên từ trái sang phải, xuống hàng giữa, rồi xuống Risk Engine.]

Khi người dùng nhập URL, hệ thống kiểm tra địa chỉ trước để hạn chế việc máy chủ bị lợi dụng truy cập vào mạng nội bộ. Sau đó, các bộ phân tích thu thập thông tin từ URL, tên miền, chứng chỉ, HTML và dấu hiệu thương hiệu.

Những thông tin này được chuẩn hóa thành 30 thuộc tính. Từ đó, phần luật tạo điểm và lời giải thích, còn mô hình XGBoost đưa ra xác suất phishing ước tính.

Riêng danh sách đen cung cấp bằng chứng trực tiếp cho Risk Engine. Kết quả tra danh sách đen không nằm trong 30 thuộc tính của mô hình.

Cuối cùng, Risk Engine tổng hợp các nguồn thành điểm rủi ro. Hệ thống lưu kết quả vào cơ sở dữ liệu rồi trả lại qua giao diện hoặc API.

Em sẽ đi cụ thể hơn vào những dấu hiệu mà các bộ phân tích thu thập.

## Slide 5 — Các bộ phân tích

Với URL, hệ thống xem các đặc điểm như độ dài, số tên miền phụ, việc dùng địa chỉ IP hoặc các ký tự bất thường. Đây là những thông tin có thể lấy ngay từ đường link.

Với domain, hệ thống tìm tuổi tên miền. Với TLS, hệ thống kiểm tra chứng chỉ khi kết nối, chẳng hạn chứng chỉ còn hạn và có phù hợp với hostname hay không.

Phần HTML tìm những dấu hiệu như ô nhập mật khẩu, trường thông tin thẻ, iframe hoặc nội dung thúc ép người dùng thực hiện hành động.

Phần thương hiệu kiểm tra tên gần giống thương hiệu đã cấu hình, rồi kết hợp thêm dấu hiệu đăng nhập. Chỉ có tên gần giống thì chưa đủ để kết luận giả mạo.

Những dữ liệu này sẽ được sử dụng như thế nào để tính điểm? Trước hết là phần luật heuristic.

## Slide 6 — Luật heuristic tạo điểm và lời giải thích

Heuristic ở đây có thể hiểu là những quy tắc được viết trước để nhận diện dấu hiệu đáng ngờ. Khi một điều kiện thỏa mãn, hệ thống cộng số điểm tương ứng và tạo lời giải thích.

Ví dụ, tên miền đăng ký chưa đến 7 ngày được cộng 30 điểm. URL dùng địa chỉ IP được cộng 25 điểm. Nếu một form gửi thông tin sang domain khác, hệ thống cộng 12 điểm.

Ngược lại, việc không dùng HTTPS chỉ cộng 5 điểm. Trong cách thiết kế này, HTTPS là một tín hiệu về kết nối, chưa đủ để quyết định website có đáng tin hay không.

Ưu điểm của phần luật là người dùng có thể biết vì sao điểm tăng. Tổng điểm luật được giới hạn trong khoảng 0 đến 100.

Tuy nhiên, luật chỉ bao phủ những điều kiện đã viết sẵn. Vì vậy đồ án bổ sung mô hình học máy để học thêm từ dữ liệu.

## Slide 7 — PhiUSIIL: dữ liệu và cách chia tập

Để huấn luyện mô hình, đồ án sử dụng bộ dữ liệu PhiUSIIL. Sau khi loại trùng, dữ liệu còn khoảng 235 nghìn URL, gồm cả URL hợp lệ và URL phishing.

Trong đó, khoảng 186 nghìn URL dùng để huấn luyện, còn hơn 49 nghìn URL dùng để đánh giá. Nhãn được thống nhất là 1 cho phishing và 0 cho hợp lệ.

Điểm cần chú ý là cách chia dữ liệu theo tên miền. Ví dụ, một website có các đường dẫn khác nhau như trang đăng nhập và trang tài khoản. Nếu chia ngẫu nhiên từng URL, các trang cùng tên miền có thể xuất hiện ở cả hai tập, khiến kết quả đánh giá thuận lợi hơn thực tế.

Vì vậy, đồ án gom các URL theo tên miền đăng ký khi chia tập để hạn chế tình trạng này.

Sau bước chuẩn bị dữ liệu, mỗi URL được chuyển thành các thuộc tính đầu vào cho mô hình.

## Slide 8 — Vector đầu vào gồm 30 thuộc tính

Mô hình không nhận trực tiếp cả một website. Nó nhận một dãy số mô tả các đặc điểm của website đó, gọi là vector thuộc tính.

Trong đồ án, vector này gồm 30 thuộc tính chia thành năm nhóm như trên slide. Nhóm URL có nhiều thuộc tính nhất, ví dụ độ dài đường link, số tên miền phụ và có dùng HTTPS hay không. Các nhóm còn lại mô tả domain, TLS, HTML, thương hiệu và chuyển hướng.

FeatureExtractor giữ tên và thứ tự thuộc tính nhất quán giữa lúc huấn luyện với lúc dự đoán.

Tuy vậy, có cùng cấu trúc đầu vào chưa có nghĩa dữ liệu ở hai giai đoạn hoàn toàn giống nhau. Chẳng hạn, dữ liệu huấn luyện thiếu thông tin chứng chỉ thật, còn khi quét trực tiếp thì hệ thống có thể kiểm tra được. Em sẽ quay lại hạn chế này ở phần sau.

Trước hết, đây là kết quả so sánh các mô hình.

## Slide 9 — XGBoost có tỷ lệ bỏ sót thấp nhất

[Chỉ lần lượt bốn cột, dừng ở XGBoost.]

Đồ án so sánh bốn mô hình: Logistic Regression, Decision Tree, Random Forest và XGBoost.

Tiêu chí chính để lựa chọn là FNR, tức tỷ lệ bỏ sót phishing. Có thể hiểu đơn giản: trong các URL thực sự là phishing, mô hình đã dự đoán nhầm bao nhiêu URL là hợp lệ. Vì thế, chỉ số này càng thấp càng tốt.

Trên tập đánh giá hiện tại, XGBoost có FNR thấp nhất, khoảng 3,47%, nên được chọn để sử dụng. Random Forest đứng khá gần, khoảng 3,56%.

Em lưu ý là chênh lệch giữa hai mô hình này khá nhỏ, tương ứng 19 URL bị bỏ sót. Do đó, kết quả cho thấy XGBoost tốt hơn theo tiêu chí lựa chọn trong lần đánh giá này, chứ chưa đủ để nói mô hình luôn vượt trội trong mọi trường hợp.

Để hiểu rõ hơn các lỗi dự đoán, em trình bày ma trận nhầm lẫn ở trang tiếp theo.

## Slide 10 — Ma trận nhầm lẫn của XGBoost

[Chỉ vào hàng Phishing, sau đó chỉ ô 772 và ô 292. Không cần đọc toàn bộ bảng.]

Trong bảng này, hàng là nhãn thực tế, còn cột là kết quả mô hình dự đoán.

Ở nhóm phishing, mô hình nhận đúng 21.466 URL, nhưng vẫn bỏ sót 772 URL. Đây là nhóm lỗi mà đồ án muốn theo dõi bằng chỉ số FNR.

Ở chiều ngược lại, có 292 URL hợp lệ bị cảnh báo nhầm là phishing. Như vậy, ngoài việc giảm bỏ sót, hệ thống vẫn cần chú ý đến trải nghiệm người dùng khi cảnh báo nhầm.

Các chỉ số tổng hợp gồm recall phishing khoảng 96,53%, F1 khoảng 97,58% và accuracy khoảng 97,85%.

Những kết quả này được đo trên tập dữ liệu đang dùng. Để biết mô hình có phù hợp với URL mới ngoài thực tế hay không, em vẫn cần một bước đánh giá độc lập hơn.

Một cách kiểm tra thêm là xem mô hình đang dựa nhiều vào thuộc tính nào.

## Slide 11 — Mô hình phụ thuộc mạnh vào tín hiệu HTTPS

[Chỉ hai thanh dài nhất. Nói chậm ở đoạn giải thích hostname_match.]

Biểu đồ này thể hiện mức quan trọng của các thuộc tính theo gain, tức mức cải thiện mà thuộc tính đóng góp khi mô hình chia các nhánh cây.

Hai thuộc tính đứng đầu là has_https và hostname_match, chiếm tổng cộng khoảng 74,1%. Điều này cho thấy mô hình hiện phụ thuộc khá nhiều vào những tín hiệu liên quan đến HTTPS.

Có một chi tiết cần phân biệt: bộ PhiUSIIL không cung cấp kết quả kiểm tra hostname của chứng chỉ thật. Trong luồng huấn luyện hiện tại, khi thiếu thông tin đó, hostname_match lấy giá trị mặc định theo scheme của URL, tức phần HTTP hoặc HTTPS.

Vì vậy, em không diễn giải biểu đồ này thành việc mô hình đã học tốt chất lượng chứng chỉ. Đây là hạn chế của cách chuẩn bị dữ liệu và là một phần cần cải thiện.

Bên cạnh luật và học máy, hệ thống còn sử dụng nguồn bằng chứng thứ ba là danh sách đen.

## Slide 12 — Danh sách đen bổ sung bằng chứng đã biết

Danh sách đen giúp hệ thống nhận diện các URL hoặc tên miền đã có trong nguồn dữ liệu cảnh báo.

Đồ án kết hợp ba nguồn là OpenPhish, URLhaus và Phishing.Database. Trong đó, URLhaus cung cấp URL độc hại nói chung, nên không nên hiểu mọi mục trong nguồn này đều là trang phishing.

Tại thời điểm lưu số liệu ngày 28 tháng 9 năm 2026, dữ liệu feed hợp nhất có 16.842 URL và 169.472 tên miền. Đây là số liệu tại một thời điểm, có thể thay đổi khi đồng bộ lại.

Hệ thống có cơ chế đồng bộ khi khởi động nếu dữ liệu cũ hơn 24 giờ. Tuy nhiên, việc một địa chỉ chưa xuất hiện trong danh sách đen không đảm bảo địa chỉ đó an toàn. Khi đó, phần luật và mô hình vẫn tiếp tục cung cấp đánh giá.

Sau khi có đủ các nguồn bằng chứng, Risk Engine sẽ tổng hợp kết quả.

## Slide 13 — Risk Engine tổng hợp điểm rủi ro

[Chỉ công thức trước, rồi chuyển xuống bảng mức rủi ro.]

Trong trường hợp thông thường, không khớp danh sách đen và có mô hình, điểm rủi ro lấy 55% từ điểm luật và 45% từ đầu ra học máy sau khi đổi về thang 100.

Ví dụ, nếu luật cho 20 điểm và mô hình ước tính 60%, thì điểm tổng hợp là 11 cộng 27, bằng 38 điểm. Theo ngưỡng của hệ thống, kết quả này thuộc mức thấp.

Nếu cả điểm luật và đầu ra mô hình cùng cao, hệ thống giảm nhẹ trọng số của ML và tăng phần luật tương ứng. Mục đích thiết kế là hạn chế tính lặp những tín hiệu xuất hiện ở cả hai nguồn. Đây là cách điều chỉnh heuristic, chưa phải một cơ chế loại bỏ hoàn toàn sự trùng lặp.

Nếu địa chỉ khớp danh sách đen, điểm được đặt tối thiểu là 85. Nếu không có mô hình, hệ thống dùng điểm luật.

Các trọng số và ngưỡng này là cấu hình của đồ án, còn cần đánh giá thêm để lựa chọn phù hợp hơn khi triển khai thực tế.

## Slide 14 — An toàn khi quét và kiểm thử

Ngoài việc kiểm tra website, bản thân công cụ quét cũng cần có biện pháp bảo vệ.

Ví dụ, nếu người dùng nhập một địa chỉ trỏ vào mạng nội bộ, máy chủ có thể bị lợi dụng để gửi yêu cầu đến nơi không nên truy cập. Rủi ro này gọi là SSRF.

Để giảm rủi ro đó, hệ thống kiểm tra DNS và IP, chặn các địa chỉ nội bộ và kiểm tra lại sau mỗi lần chuyển hướng. Việc kiểm tra lại cần thiết vì địa chỉ ban đầu có thể hợp lệ nhưng sau đó chuyển sang một địa chỉ khác.

Hệ thống cũng giới hạn tối đa 3 lần chuyển hướng, dung lượng HTML 2 MB, cùng thời gian chờ kết nối và đọc dữ liệu.

Về kiểm thử, cả 16 test hiện tại đều chạy thành công. Kết quả này xác nhận các tình huống đã viết test hoạt động đúng, nhưng chưa bao phủ mọi tình huống thực tế.

Sau phần xử lý bên trong, em xin chuyển sang giao diện sử dụng.

## Slide 15 — Demo: nhập URL và xem lịch sử

[Chỉ ô nhập URL và khu vực “Vừa kiểm tra”. Nếu demo trực tiếp, chuyển sang trình duyệt ở đây.]

Đây là trang chủ của ứng dụng. Người dùng nhập tên miền hoặc URL vào ô này rồi nhấn Phân tích.

Ứng dụng sẽ chuyển sang màn hình tiến trình, sau đó hiển thị báo cáo khi có kết quả. Người dùng không cần tự thực hiện từng bước tra tên miền hay kiểm tra chứng chỉ.

Phía dưới là những địa chỉ vừa kiểm tra. Khi chọn một mục, người dùng có thể mở lại báo cáo đã lưu để xem điểm và các dấu hiệu của lần quét đó.

Ngoài giao diện web, hệ thống cũng cung cấp API cho việc gọi chức năng quét từ chương trình khác.

Để minh họa cách đọc kết quả, em sẽ dùng một lượt quét đã lưu ở trang tiếp theo.

*Nếu đang demo trực tiếp và phải chờ, có thể nói: “Trong lúc hệ thống đang thu thập thông tin, em xin mở một kết quả đã lưu để trình bày rõ hơn các thành phần của báo cáo.”*

## Slide 16 — Demo: điểm tổng hợp và dấu hiệu cụ thể

[Chỉ điểm 60, phần điểm luật và ML, rồi chỉ trạng thái thiếu dữ liệu.]

Ở ví dụ này, hệ thống trả về 60 trên 100 điểm, tương ứng mức rủi ro trung bình.

Nếu nhìn từng thành phần, điểm luật là 28, đầu ra mô hình khoảng 99,9%, và địa chỉ không khớp danh sách đen. Khi áp dụng trọng số đã trình bày, kết quả tổng hợp làm tròn thành 60 điểm.

Ví dụ này cho thấy điểm rủi ro và đầu ra ML là hai giá trị khác nhau. Con số 99,9% là ước tính của mô hình hiện tại, chưa phải độ chắc chắn đã được kiểm chứng ngoài thực tế.

Một điểm khác cần chú ý là trạng thái thiếu dữ liệu, hay partial. Điều đó có nghĩa là hệ thống chưa thu thập đủ thông tin cho lượt quét này. Vì vậy, người dùng cần đọc trạng thái này cùng các dấu hiệu và checklist.

Ở phiên bản hiện tại, một số mục chưa phân biệt rõ “chưa biết” với “không phát hiện”. Đây cũng là điểm em muốn cải thiện ở giao diện.

## Slide 17 — Hạn chế của phiên bản hiện tại

Qua phần đánh giá và demo, em thấy phiên bản hiện tại còn một số hạn chế.

Trước hết, tập test đang được dùng để so sánh và lựa chọn mô hình. Vì vậy, kết quả này chưa thay thế được một lần đánh giá cuối trên tập độc lập chưa tham gia lựa chọn.

Tiếp theo, mô hình phụ thuộc nhiều vào tín hiệu HTTPS, trong khi dữ liệu huấn luyện thiếu tuổi tên miền và kết quả kiểm tra chứng chỉ thật.

Về thu thập, hệ thống mới phân tích HTML tĩnh nên có thể bỏ qua nội dung do JavaScript tạo ra. Việc tra cứu DNS, RDAP hoặc WHOIS cũng có thể thất bại và dẫn đến thiếu dữ liệu.

Cuối cùng, cách trình bày kết quả cần giúp người dùng phân biệt rõ giữa không tìm thấy dấu hiệu và chưa có đủ thông tin để kiểm tra.

Từ những hạn chế này, em xác định các hướng phát triển tiếp theo.

## Slide 18 — Hướng phát triển

Ưu tiên đầu tiên của em là cải thiện cách đánh giá. Cụ thể, em dự định tách riêng tập validation để chọn mô hình, giữ tập test cho đánh giá cuối, và kiểm tra thêm trên URL thu thập ở thời điểm mới hơn.

Với dữ liệu, em muốn bổ sung tuổi domain và kết quả TLS thật. Em cũng sẽ thử bỏ nhóm thuộc tính HTTPS để đo xem chất lượng mô hình thay đổi như thế nào, thay vì chỉ nhìn vào biểu đồ độ quan trọng.

Một bước khác là hiệu chỉnh xác suất, để đầu ra của mô hình phản ánh tốt hơn tỷ lệ đúng quan sát được trên dữ liệu đánh giá.

Với ứng dụng, em dự định cải thiện trạng thái chưa biết trong checklist, bổ sung khả năng phân tích trang JavaScript và mở rộng danh sách thương hiệu Việt Nam.

Sau khi các phần đó ổn định hơn, hệ thống có thể phát triển thành tiện ích trình duyệt. Đây là các hướng dự kiến, chưa phải chức năng đã hoàn thành.

## Slide 19 — Kết luận

Qua đồ án này, em đã xây dựng được một ứng dụng Python xử lý từ bước nhận URL, thu thập dấu hiệu, tính điểm cho đến lưu trữ và hiển thị kết quả.

Hệ thống kết hợp luật heuristic, mô hình XGBoost và danh sách đen. Trên tập đánh giá hiện tại, XGBoost đạt FNR khoảng 3,47% và F1 khoảng 97,58%.

Kết quả mà em muốn nhấn mạnh là người dùng có thể xem cả điểm rủi ro lẫn lý do tạo ra điểm đó. Đồng thời, đồ án cũng giúp em thấy rõ những vấn đề cần xử lý khi đưa mô hình vào ứng dụng, nhất là dữ liệu thiếu và khác biệt giữa huấn luyện với quét thực tế.

Phần trình bày của em đến đây là kết thúc. Em cảm ơn thầy cô đã lắng nghe và mong nhận được góp ý để hoàn thiện đồ án.

[Dừng tại đây để nhận câu hỏi. Không cần tự động trình bày hai slide phụ lục.]

## Slide 20 — Phụ lục: kết quả đầy đủ của 4 mô hình

*Dùng khi thầy cô muốn xem thêm các chỉ số hoặc hỏi vì sao chọn XGBoost.*

Dạ, đây là bảng so sánh đầy đủ của bốn mô hình trên cùng tập đánh giá.

Nếu xét FNR, XGBoost có tỷ lệ bỏ sót thấp nhất. XGBoost cũng có F1 và accuracy cao nhất trong lần đánh giá này. Tuy nhiên, nếu chỉ nhìn precision thì Decision Tree nhỉnh hơn một chút. Như vậy, lựa chọn mô hình còn phụ thuộc vào tiêu chí mình ưu tiên.

Trong đồ án, tiêu chí lựa chọn ưu tiên FNR. Cụ thể, XGBoost bỏ sót 772 URL phishing, trong khi Random Forest bỏ sót 791 URL, chênh lệch 19 URL.

Vì chênh lệch khá nhỏ, em chỉ kết luận XGBoost là lựa chọn theo kết quả hiện tại. Để có kết luận chắc chắn hơn, em cần thêm dữ liệu độc lập và đánh giá độ ổn định của kết quả.

## Slide 21 — Phụ lục: trao đổi khi bảo vệ

*Không đọc liên tục tất cả câu trả lời. Chọn phần phù hợp với câu hỏi của thầy cô.*

### Nếu được hỏi: “Vì sao em ưu tiên FNR thay vì accuracy?”

Dạ, vì em muốn theo dõi trực tiếp số trường hợp phishing bị dự đoán là hợp lệ. Accuracy cho biết tỷ lệ đúng chung, còn FNR tập trung vào nhóm lỗi bỏ sót mà bài toán này cần chú ý. Tuy nhiên, em vẫn theo dõi precision và F1 để tránh chỉ giảm bỏ sót bằng cách cảnh báo quá nhiều.

### Nếu được hỏi: “Điểm rủi ro 80 có nghĩa là 80% khả năng lừa đảo không?”

Dạ không ạ. Điểm 80 là chỉ số tổng hợp từ luật, đầu ra mô hình và danh sách đen. Nó dùng để xếp mức rủi ro theo ngưỡng của hệ thống. Xác suất ML được hiển thị riêng, và ngay cả giá trị đó hiện cũng chưa được hiệu chỉnh để coi là độ chắc chắn ngoài thực tế.

### Nếu được hỏi: “Không có trong danh sách đen thì có an toàn không?”

Dạ, mình chưa thể kết luận như vậy. Một địa chỉ có thể chưa xuất hiện trong nguồn dữ liệu đang dùng. Vì vậy, khi không khớp danh sách đen, hệ thống vẫn kiểm tra các dấu hiệu và sử dụng mô hình để tính điểm.

### Nếu được hỏi: “WHOIS thất bại thì hệ thống xử lý thế nào?”

Dạ, hệ thống giữ tuổi tên miền là chưa rõ, không coi là tên miền mới tạo 0 ngày. Phần luật có kiểm tra cờ xác định được tuổi domain hay chưa trước khi cộng điểm theo tuổi. Lượt quét có thể được đánh dấu thiếu dữ liệu, còn các bằng chứng khác vẫn được sử dụng.

### Nếu được hỏi thêm: “Vì sao không đưa blacklist vào mô hình?”

Dạ, đồ án tách blacklist thành nguồn bằng chứng riêng. Nếu thông tin danh sách đen có liên hệ quá gần với cách tạo nhãn dữ liệu, đưa nó vào đầu vào có thể làm kết quả đánh giá thuận lợi hơn nhưng không phản ánh tốt khả năng nhận diện URL mới. Tách riêng cũng giúp người dùng thấy rõ khi nào điểm cao là do khớp một nguồn cảnh báo.

### Nếu được hỏi thêm: “Mô hình có thực sự học tuổi domain và chứng chỉ không?”

Dạ, trong schema có các thuộc tính đó, nhưng bộ dữ liệu hiện tại thiếu tuổi tên miền và kết quả chứng chỉ thật. Vì vậy, em chưa thể nói mô hình đã học được đầy đủ những tín hiệu này. Riêng hostname_match trong luồng huấn luyện đang dùng giá trị mặc định theo HTTP hoặc HTTPS khi thiếu dữ liệu. Khi quét thực tế, thông tin thu được vẫn có thể dùng trong phần luật, nhưng sự khác biệt này là điểm cần cải thiện của mô hình.

### Nếu được hỏi thêm: “Vì sao chọn trọng số luật 55%, ML 45%?”

Dạ, đây là trọng số cấu hình heuristic của phiên bản hiện tại, với phần luật được đặt cao hơn một chút. Em chưa có thí nghiệm đủ để khẳng định đây là bộ trọng số tối ưu. Hướng tiếp theo là đánh giá nhiều cách phối hợp trên tập validation độc lập, rồi mới cố định trọng số và kiểm tra trên tập test.

### Nếu được hỏi thêm: “16 test pass có chứng minh hệ thống an toàn không?”

Dạ, chưa đủ để kết luận an toàn toàn diện. Nó cho thấy các trường hợp đã viết kiểm thử đang cho kết quả đúng. Em vẫn cần mở rộng tình huống kiểm thử, đặc biệt là xử lý chuyển hướng, lỗi mạng và dữ liệu thiếu, cùng việc đánh giá khi triển khai thực tế.

---

## Gợi ý tập nói

- Tập liền slide 1–19 một lần và bấm giờ. Hai slide phụ lục chỉ tập theo dạng hỏi đáp.
- Không đọc toàn bộ bảng. Ở slide 9–10, tập trung vào FNR, số URL bỏ sót và ý nghĩa của chúng.
- Dành thêm thời gian cho slide 4, 11, 13 và 16 vì đây là những phần thể hiện cách hệ thống hoạt động và khả năng giải thích kết quả.
- Nếu cần rút ngắn, nói gọn slide công nghệ và các nhóm thuộc tính, giữ phần kết quả, demo và hạn chế.
- Khi demo mạng chậm, chuyển sang kết quả đã lưu hoặc ảnh trong slide. Nói rõ đó là kết quả đã lưu.

**Cơ sở nội dung:** Bộ slide báo cáo 21 trang, số liệu trong `artifacts/phishing_model_v1/`, cấu hình và mã nguồn của đồ án. Các hướng phát triển trong kịch bản là đề xuất, không phải chức năng đã triển khai.
