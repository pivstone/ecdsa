defmodule NifNotLoadedError do
  defexception message: "nif not loaded"
end

defmodule Ecdsa do
  use Rustler, otp_app: :ecdsa, crate: "ecdsa"

  def verify(_key,_msg,_sig), do: exit(:nif_not_loaded)
  def add(_a,_b), do: exit(:nif_not_loaded)
end
