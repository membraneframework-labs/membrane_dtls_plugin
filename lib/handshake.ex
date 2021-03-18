defmodule Membrane.DTLS.Handshake do
  @moduledoc """
  Module responsible for performing DTLS and DTLS-SRTP handshake.

  As `handshake_opts` in Sink/Source there should be passed keyword list containing following
  fields:
  * client_mode :: boolean()
  * dtls_srtp :: boolean()

  For the rest of field meanings please refer to `ExDTLS` library documentation.
  """
  @behaviour Membrane.ICE.Handshake

  alias Membrane.ICE.Handshake

  require Membrane.Logger

  @impl Handshake
  def init(id, parent, opts) do
    {:ok, dtls} =
      ExDTLS.start_link(
        client_mode: opts[:client_mode],
        dtls_srtp: opts[:dtls_srtp]
      )

    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(dtls)
    state = %{:dtls => dtls, :client_mode => opts[:client_mode], :id => id, :parent => parent}
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
end
