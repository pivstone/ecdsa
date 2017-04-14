defmodule EcdsaTest do
  use ExUnit.Case
  doctest Ecdsa

  test "the truth" do
    assert Ecdsa.add(1,1) == {:ok,2}
  end

  test "verify" do
    sig = File.read!("test/data/sig.json")|>String.trim |> Base.url_decode64!(padding: false)
    msg = File.read!("test/data/msg.json")|>String.trim
    [x,y] = File.read!("test/data/key.json")|>String.split()
    x = x|> Base.url_decode64!(padding: false)
    y = y|> Base.url_decode64!(padding: false)
    key = <<4>> <> x <> y
    #key = <<4>><>Base.url_decode64!(x,padding: false) <> Base.url_decode64!(y,padding: false)
    key2 = "0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e13b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0"
    msg2 = ""
    sig2 = "341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b88d3796c6555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1"
    #IO.puts inspect Ecdsa.verify(key2,msg2,sig2)
    IO.puts inspect Ecdsa.verify(key|> Base.encode16(case: :lower),msg|>Base.encode16(case: :lower) ,sig|>Base.encode16(case: :lower))
  end

  
end