use test_server;

#[tokio::main(flavor = "current_thread")]
async fn main() {
  test_server::v1::main().await;
}
