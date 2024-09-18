package golang

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"golang.org/x/mod/modfile"
	"io"
)

type goLibraryCataloger struct{}

func newGoLibraryCataloger() *goLibraryCataloger {
	return &goLibraryCataloger{}
}

func (c *goLibraryCataloger) parseGoModFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read go module: %w", err)
	}

	modPath := modfile.ModulePath(contents)
	pkgInfo, err := libraries(ctx, modPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine package info: %w", err)
	}
	pkgInfoNoOp(pkgInfo)
	return nil, nil, nil
}

func pkgInfoNoOp(info []pkgInfo) []*pkg.Package {
	return []*pkg.Package{}
}

// These are the steps we take to find libraries:
//  1. we list all modules and all packages
//  2. for each package, we find a list of candidates
//  3. we deduplicate all candidates
//  4. for each candidate, we classify if the candidate is a license file
//  5. for each package, we select the first candidates that is a license
//     file & add the package to a list of packages for that license file
//  6. we return an array of libraries (which are the license files, the
//     found licenses in that file, all the packages that had that file as
//     its first candidate and the module in which those packages live)
func libraries(ctx context.Context, modPath string) ([]pkgInfo, error) {
	cfg := &packages.Config{
		Context: ctx,
		Mode:    packages.NeedImports | packages.NeedDeps | packages.NeedFiles | packages.NeedName | packages.NeedModule,
		Tests:   true, // TODO: should we inject this to be configurable
	}

	rootPkgs, err := packages.Load(cfg, modPath)
	if err != nil {
		return nil, err
	}

	vendoredSearch := []*Module{}
	for _, parentPkg := range rootPkgs {
		if parentPkg.Module == nil {
			continue
		}

		module := newModule(parentPkg.Module)
		if module.Dir == "" {
			continue
		}

		vendoredSearch = append(vendoredSearch, module)
	}

	allPackages := []pkgInfo{}
	{
		pkgErrorOccurred := false
		packages.Visit(rootPkgs, func(p *packages.Package) bool {
			if len(p.Errors) > 0 {
				pkgErrorOccurred = true
				return false
			}
			if len(p.OtherFiles) > 0 {
				// log.Warningf("%q contains non-Go code that can't be inspected for further dependencies:\n%s", p.PkgPath, strings.Join(p.OtherFiles, "\n"))
			}

			var pkgDir string
			switch {
			case len(p.GoFiles) > 0:
				pkgDir = filepath.Dir(p.GoFiles[0])
			case len(p.CompiledGoFiles) > 0:
				pkgDir = filepath.Dir(p.CompiledGoFiles[0])
			case len(p.OtherFiles) > 0:
				pkgDir = filepath.Dir(p.OtherFiles[0])
			default:
				// This package is empty - nothing to do.
				return true
			}

			module := newModule(p.Module)
			allPackages = append(allPackages, pkgInfo{
				pkgPath:    p.PkgPath,
				modulePath: module.Path,
				pkgDir:     pkgDir,
				moduleDir:  module.Dir,
			})
			return true
		}, nil)
		if pkgErrorOccurred {
			return nil, fmt.Errorf("failed to parse go modules")
		}
	}
	return allPackages, nil
}

func newModule(mod *packages.Module) *Module {
	tmp := *mod
	if tmp.Replace != nil {
		tmp = *tmp.Replace
	}

	// The +incompatible suffix does not affect module version.
	// ref: https://golang.org/ref/mod#incompatible-versions
	tmp.Version = strings.TrimSuffix(tmp.Version, "+incompatible")
	return &Module{
		Path:    tmp.Path,
		Version: tmp.Version,
		Dir:     tmp.Dir,
	}
}

type Module struct {
	Path    string
	Version string
	Dir     string
}

type pkgInfo struct {
	// pkgPath is the import path of the package.
	pkgPath string
	// modulePath is the module path of the package.
	modulePath string

	// pkgDir is the directory containing the package's source code.
	pkgDir string
	// moduleDir is the directory containing the module's source code.
	moduleDir string
}
