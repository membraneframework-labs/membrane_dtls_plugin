defmodule Membrane.Libnice.Support.TestSender do
  @moduledoc false

  use Membrane.Pipeline

  @impl true
  def handle_init(opts) do
    children = %{
      source: Membrane.Libnice.Support.TestSource,
      libnice: %Membrane.Libnice.Bin{
        stun_servers: [%{server_addr: "stun1.l.google.com", server_port: 19_302}],
        controlling_mode: true,
        handshake_module: opts[:handshake_module],
        handshake_opts: opts[:handshake_opts]
      }
    }

    pad = Pad.ref(:input, 1)
    links = [link(:source) |> via_out(:output) |> via_in(pad) |> to(:libnice)]

    spec = %ParentSpec{children: children, links: links}
    {{:ok, spec: spec}, %{}}
  end
end
