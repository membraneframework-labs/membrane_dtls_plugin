defmodule Membrane.DTLS.Plugin.Mixfile do
  use Mix.Project

  @version "0.7.0"
  @github_url "https://github.com/membraneframework/membrane_dtls_plugin"

  def project do
    [
      app: :membrane_dtls_plugin,
      version: @version,
      elixir: "~> 1.10",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # hex
      description:
        "DTLS (and DTLS-SRTP) implementation of Handshake behaviour for Membrane Libnice plugin",
      package: package(),

      # docs
      name: "Membrane DTLS plugin",
      source_url: @github_url,
      homepage_url: "https://membraneframework.org",
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: []
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:membrane_core, "~> 0.8.0"},
      {:membrane_libnice_plugin, "~> 0.9.0"},
      {:ex_dtls, "~> 0.10.0"},
      {:ex_doc, "~> 0.23", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0.0", only: :dev, runtime: false},
      {:credo, "~> 1.5", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Membrane Team"],
      licenses: ["Apache 2.0"],
      links: %{
        "GitHub" => @github_url,
        "Membrane Framework Homepage" => "https://membraneframework.org"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE"],
      source_ref: "v#{@version}",
      nest_modules_by_prefix: [Membrane.DTLS]
    ]
  end
end
