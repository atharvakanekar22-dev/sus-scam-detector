import Link from "next/link";

export function BrandHeader() {
  return (
    <header className="flex justify-center py-9 sm:py-11" role="banner">
      <Link
        href="/"
        aria-label="SUS home"
        onClick={(event) => {
          event.preventDefault();
          window.location.reload();
        }}
        className="group relative inline-flex flex-col items-center rounded-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#177D69]"
      >
        <span className="pointer-events-none absolute bottom-full left-1/2 mb-[-0.25rem] -translate-x-1/2 translate-y-1 whitespace-nowrap text-xs font-medium tracking-wide text-[#52645E] opacity-0 transition-all duration-200 group-hover:translate-y-0 group-hover:opacity-100 group-focus-visible:translate-y-0 group-focus-visible:opacity-100">
          Scam Message Scanner
        </span>
        <h1 className="text-[6rem] font-semibold tracking-[-0.085em] text-[#17312D] transition-transform duration-200 group-hover:scale-105 sm:text-[7rem]">
          SUS
        </h1>
      </Link>
    </header>
  );
}
