defmodule Membrane.DTLS.Handshake do
  @moduledoc """
  Module responsible for performing DTLS and DTLS-SRTP handshake.

  `handshake_opts` in `membrane_ice_plugin` should be the same as in `t:ExDTLS.opts_t/0`.
  """
  @behaviour Membrane.ICE.Handshake

  alias Membrane.ICE.Handshake

  require Membrane.Logger

  @impl Handshake
  def init(_id, _parent, opts) do
    {:ok, dtls} = ExDTLS.start_link(opts)
    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(dtls)
    state = %{:dtls => dtls, :client_mode => opts[:client_mode]}
    {:ok, fingerprint, state}
  end

  @impl Handshake
  def connection_ready(%{client_mode: false}), do: :ok

  @impl Handshake
  def connection_ready(%{dtls: dtls}) do
    ExDTLS.do_handshake(dtls)
  end

  @impl Handshake
  def process(data, %{dtls: dtls}) do
    case ExDTLS.process(dtls, data) do
      :handshake_want_read -> :ok
      other -> other
    end
  end

  @impl Handshake
  def is_hsk_packet(<<head, _rest::binary()>> = packet, _state) do
    head in 20..63 and byte_size(packet) >= 13
  end

  @impl Handshake
  def stop(%{dtls: dtls}) do
    ExDTLS.stop(dtls)
  end
end
