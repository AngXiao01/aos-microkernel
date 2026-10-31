//! Physical or virtual address ranges, and fixed-capacity lists of them (no heap).

/// The half-open range `[start, end)`; empty if `start >= end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
}

pub const fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

pub const fn align_up(x: usize, align: usize) -> usize {
    align_down(x + align - 1, align)
}

impl Region {
    pub const EMPTY: Region = Region { start: 0, end: 0 };

    pub const fn new(start: usize, end: usize) -> Region {
        Region { start, end }
    }

    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub const fn contains(&self, addr: usize) -> bool {
        self.start <= addr && addr < self.end
    }

    pub const fn overlaps(&self, other: &Region) -> bool {
        !self.is_empty() && !other.is_empty() && self.start < other.end && other.start < self.end
    }

    /// The largest `align`-aligned range inside `self`.
    pub const fn align_inward(&self, align: usize) -> Region {
        Region::new(align_up(self.start, align), align_down(self.end, align))
    }

    /// The smallest `align`-aligned range containing `self`.
    pub const fn align_outward(&self, align: usize) -> Region {
        Region::new(align_down(self.start, align), align_up(self.end, align))
    }
}

#[derive(Debug)]
pub struct ListFull;

#[derive(Clone, Copy)]
pub struct RegionList<const N: usize> {
    items: [Region; N],
    len: usize,
}

impl<const N: usize> RegionList<N> {
    pub const fn new() -> RegionList<N> {
        RegionList { items: [Region::EMPTY; N], len: 0 }
    }

    /// Appends `region`; empty regions are dropped.
    pub fn push(&mut self, region: Region) -> Result<(), ListFull> {
        if region.is_empty() {
            return Ok(());
        }
        let slot = self.items.get_mut(self.len).ok_or(ListFull)?;
        *slot = region;
        self.len += 1;
        Ok(())
    }

    pub fn as_slice(&self) -> &[Region] {
        &self.items[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [Region] {
        &mut self.items[..self.len]
    }

    pub fn total(&self) -> usize {
        self.as_slice().iter().map(Region::len).sum()
    }

    /// Removes `hole` from every region, splitting regions where needed.
    pub fn subtract(&mut self, hole: Region) -> Result<(), ListFull> {
        let mut out = RegionList::new();
        for r in self.as_slice() {
            if r.overlaps(&hole) {
                out.push(Region::new(r.start, hole.start.min(r.end)))?;
                out.push(Region::new(hole.end.max(r.start), r.end))?;
            } else {
                out.push(*r)?;
            }
        }
        *self = out;
        Ok(())
    }

    pub fn sort_by_start(&mut self) {
        self.as_mut_slice().sort_unstable_by_key(|r| r.start);
    }
}

#[cfg(feature = "ktest")]
mod tests {
    use super::*;

    fn list(regions: &[Region]) -> RegionList<4> {
        let mut l = RegionList::new();
        for r in regions {
            l.push(*r).unwrap();
        }
        l
    }

    ktest! {
        fn subtract_splits_and_trims() {
            let r = |a, b| Region::new(a, b);
            let mut l = list(&[r(0, 100)]);
            kunwrap!(l.subtract(r(40, 60)));
            kassert_eq!(l.as_slice(), &[r(0, 40), r(60, 100)]);
            kunwrap!(l.subtract(r(0, 10)));
            kunwrap!(l.subtract(r(90, 200)));
            kassert_eq!(l.as_slice(), &[r(10, 40), r(60, 90)]);
            kunwrap!(l.subtract(r(40, 60)));
            kassert_eq!(l.as_slice(), &[r(10, 40), r(60, 90)]);
            kunwrap!(l.subtract(r(0, 1000)));
            kassert_eq!(l.as_slice().len(), 0);
        }

        fn subtract_reports_overflow() {
            let mut l = list(&[Region::new(0, 10), Region::new(20, 30), Region::new(40, 50), Region::new(60, 70)]);
            kassert!(l.subtract(Region::new(5, 6)).is_err());
        }

        fn alignment() {
            kassert_eq!(Region::new(0x1001, 0x3fff).align_inward(0x1000), Region::new(0x2000, 0x3000));
            kassert_eq!(Region::new(0x1001, 0x3fff).align_outward(0x1000), Region::new(0x1000, 0x4000));
            kassert!(Region::new(0x1001, 0x1fff).align_inward(0x1000).is_empty());
        }
    }
}
