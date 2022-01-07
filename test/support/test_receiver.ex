defmodule Membrane.Libnice.Support.TestReceiver do
  @moduledoc false

  use Membrane.Pipeline

  @impl true
  def handle_init(opts) do
    children = %{
      libnice: %Membrane.Libnice.Bin{
        stun_servers: [%{server_addr: "stun1.l.google.com", server_port: 19_302}],
        controlling_mode: false,
        handshake_module: opts[:handshake_module],
        handshake_opts: opts[:handshake_opts]
      },
      sink: Membrane.Testing.Sink
    }

    pad = Pad.ref(:output, 1)
    links = [link(:libnice) |> via_out(pad) |> to(:sink)]

    spec = %ParentSpec{
      children: children,
      links: links
    }

    {{:ok, spec: spec}, %{}}
  end
end
