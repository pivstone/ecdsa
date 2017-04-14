defmodule EcdsaTest do
  use ExUnit.Case
  doctest Ecdsa

  test "the truth" do
    assert Ecdsa.add(1,1) == {:ok,2}
  end

  test "verify I with fixed" do
    key = "0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e13b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0"
    msg = ""
    sig = "341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b88d3796c6555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1"
    assert Ecdsa.verify(key,msg,sig) == true
  end

  test "verify II" do
    sig = File.read!("test/data/sig.json")|>String.trim |> Base.url_decode64!(padding: false)
    msg = File.read!("test/data/msg.json")|>String.trim
    [x,y] = File.read!("test/data/key.json")|>String.split()
    x = x|> Base.url_decode64!(padding: false)
    y = y|> Base.url_decode64!(padding: false)
    key = <<4>> <> x <> y
    assert Ecdsa.verify(key|> Base.encode16(case: :lower),msg|>Base.encode16(case: :lower) ,sig|>Base.encode16(case: :lower)) == true
  end

  test "verify III invalid msg" do
    key = "0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e13b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0"
    msg = "04"
    sig = "341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b88d3796c6555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1"
    assert Ecdsa.verify(key,msg,sig) == false
  end

  test "verify IV with Asn.1" do
    key = "04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"
    msg = "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3"
    sig = "3045022100bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f022017c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c"
    assert Ecdsa.verify(key,msg,sig) == true
  end
end
